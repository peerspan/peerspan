package host

import (
	"net/http"
	"strconv"
)

// pageParams reads after (default 0) and limit (default 100).
func pageParams(r *http.Request) (int64, int64, error) {
	after, limit := int64(0), int64(100)
	var err error
	if v := r.URL.Query().Get("after"); v != "" {
		after, err = strconv.ParseInt(v, 10, 64)
	}
	if v := r.URL.Query().Get("limit"); v != "" && err == nil {
		limit, err = strconv.ParseInt(v, 10, 64)
	}
	if err != nil {
		return 0, 0, ErrInvalid
	}
	return after, limit, nil
}

func taskPeerRoutes(mux *http.ServeMux, store *Store, sender func(http.ResponseWriter, *http.Request) (string, bool)) {
	mux.HandleFunc("POST /peer/v1/tasks", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		var request TaskRequest
		if !decode(w, r, &request, "task_id", "grant_id", "policy", "target_agent_id", "deadline", "input", "origin") {
			return
		}
		st, err := store.AcceptTask(r.Context(), id, request)
		respond(w, http.StatusOK, st, err)
	})
	mux.HandleFunc("GET /peer/v1/tasks/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		st, err := store.SubmitterTask(r.Context(), id, r.PathValue("id"))
		respond(w, http.StatusOK, st, err)
	})
	mux.HandleFunc("GET /peer/v1/tasks/{id}/events", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		after, limit, err := pageParams(r)
		if err != nil {
			respond(w, 0, nil, err)
			return
		}
		events, err := store.SubmitterTaskEvents(r.Context(), id, r.PathValue("id"), after, limit)
		respond(w, http.StatusOK, events, err)
	})
	mux.HandleFunc("POST /peer/v1/tasks/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		if !decode(w, r, &struct{}{}) {
			return
		}
		st, err := store.RequestTaskCancel(r.Context(), id, r.PathValue("id"))
		respond(w, http.StatusOK, st, err)
	})
}

func localTaskRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("POST /v1/tasks", func(w http.ResponseWriter, r *http.Request) {
		var request SubmitTask
		if !decode(w, r, &request, "peer_host_id", "task_id", "grant_id?", "target_agent_id", "deadline", "input", "origin") {
			return
		}
		out, err := store.PrepareOutboundTask(r.Context(), request)
		if err == nil && out.SubmitState == submitUnknown {
			out, err = store.ExchangeTask(r.Context(), out.PeerHostID, out.Request.TaskID, false)
		}
		respond(w, http.StatusOK, out, err)
	})
	mux.HandleFunc("GET /v1/tasks", func(w http.ResponseWriter, r *http.Request) {
		after, limit, err := pageParams(r)
		if err != nil {
			respond(w, 0, nil, err)
			return
		}
		items, err := store.OutboundTasks(r.Context(), after, limit)
		respond(w, http.StatusOK, items, err)
	})
	mux.HandleFunc("GET /v1/tasks/{peer}/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := store.OutboundTask(r.Context(), r.PathValue("peer"), r.PathValue("id"))
		respond(w, http.StatusOK, out, err)
	})
	mux.HandleFunc("GET /v1/tasks/{peer}/{id}/events", func(w http.ResponseWriter, r *http.Request) {
		after, limit, err := pageParams(r)
		if err != nil {
			respond(w, 0, nil, err)
			return
		}
		events, err := store.OutboundTaskEvents(r.Context(), r.PathValue("peer"), r.PathValue("id"), after, limit)
		respond(w, http.StatusOK, events, err)
	})
	mux.HandleFunc("POST /v1/tasks/{peer}/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		out, err := store.CancelOutboundTask(r.Context(), r.PathValue("peer"), r.PathValue("id"))
		respond(w, http.StatusOK, out, err)
	})
}

func adapterTaskRoutes(mux *http.ServeMux, store *Store, token func(*http.Request) AdapterAuth) {
	mux.HandleFunc("POST /adapter/v1/tasks/next", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		h, err := store.NextTask(r.Context(), token(r))
		respond(w, http.StatusOK, h, err)
	})
	mux.HandleFunc("POST /adapter/v1/tasks/cancels/next", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		h, err := store.NextTaskCancel(r.Context(), token(r))
		respond(w, http.StatusOK, h, err)
	})
	type changeBody struct {
		Reason  *string `json:"reason"`
		Message *string `json:"message"`
		Status  *string `json:"status"`
		Output  *string `json:"output"`
	}
	for op, fields := range map[string][]string{"accept": nil, "reject": {"reason"}, "progress": {"message"}, "complete": {"status", "output"}, "cancelled": nil} {
		mux.HandleFunc("POST /adapter/v1/tasks/{id}/"+op, func(w http.ResponseWriter, r *http.Request) {
			var body changeBody
			if !decode(w, r, &body, fields...) {
				return
			}
			text := func(v *string) string {
				if v == nil {
					return ""
				}
				return *v
			}
			missing := map[string]bool{"reason": body.Reason == nil, "message": body.Message == nil, "status": body.Status == nil, "output": body.Output == nil}
			for _, field := range fields {
				if missing[field] {
					respond(w, 0, nil, ErrInvalid)
					return
				}
			}
			st, err := store.ChangeTask(r.Context(), token(r), r.PathValue("id"), TaskChange{Op: op, Reason: text(body.Reason), Message: text(body.Message), Status: text(body.Status), Output: text(body.Output)})
			respond(w, http.StatusOK, st, err)
		})
	}
	mux.HandleFunc("POST /adapter/v1/delegations", func(w http.ResponseWriter, r *http.Request) {
		var req AdapterDelegate
		if !decode(w, r, &req, "destination", "task_id", "input") {
			return
		}
		out, err := store.PrepareAdapterTask(r.Context(), token(r), req)
		if err == nil && out.SubmitState == submitUnknown {
			out, err = store.ExchangeTask(r.Context(), out.PeerHostID, out.Request.TaskID, false)
		}
		respond(w, http.StatusOK, out, err)
	})
	mux.HandleFunc("GET /adapter/v1/delegations/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := store.AdapterTask(r.Context(), token(r), r.PathValue("id"))
		respond(w, http.StatusOK, out, err)
	})
	mux.HandleFunc("POST /adapter/v1/task-updates/next", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		h, err := store.NextTaskUpdate(r.Context(), token(r))
		respond(w, http.StatusOK, h, err)
	})
	mux.HandleFunc("POST /adapter/v1/task-updates/{id}/forwarded", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		d, err := store.TaskUpdateForwarded(r.Context(), token(r), r.PathValue("id"))
		respond(w, http.StatusOK, d, err)
	})
}
