package host

import "net/http"

func adapterOutboundRoutes(mux *http.ServeMux, store *Store, token func(*http.Request) AdapterAuth) {
	mux.HandleFunc("GET /adapter/v1/destinations", func(w http.ResponseWriter, r *http.Request) {
		d, err := store.Destinations(r.Context(), token(r))
		respond(w, 200, d, err)
	})
	mux.HandleFunc("POST /adapter/v1/send", func(w http.ResponseWriter, r *http.Request) {
		var req AdapterSend
		if !decode(w, r, &req, "destination", "request_id", "content") {
			return
		}
		out, err := store.PrepareAdapterSend(r.Context(), token(r), req)
		if err == nil {
			out, err = store.Exchange(r.Context(), out, false)
		}
		respond(w, 200, out, err)
	})
	mux.HandleFunc("GET /adapter/v1/sends/{id}", func(w http.ResponseWriter, r *http.Request) {
		status, err := store.AdapterSendStatus(r.Context(), token(r), r.PathValue("id"))
		respond(w, 200, status, err)
	})
	mux.HandleFunc("POST /adapter/v1/replies/next", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		h, err := store.NextReply(r.Context(), token(r))
		respond(w, 200, h, err)
	})
	mux.HandleFunc("POST /adapter/v1/replies/{id}/forwarded", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		d, err := store.ReplyForwarded(r.Context(), token(r), r.PathValue("id"))
		respond(w, 200, d, err)
	})
}
func localOutboundRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("GET /v1/outbound/{peer}/{id}/origin", func(w http.ResponseWriter, r *http.Request) {
		out, err := store.OutboundOrigin(r.Context(), r.PathValue("peer"), r.PathValue("id"))
		respond(w, 200, out, err)
	})
	mux.HandleFunc("POST /v1/adapter-routes", func(w http.ResponseWriter, r *http.Request) {
		var req CreateOutboundRoute
		if !decode(w, r, &req, "adapter_id", "name", "peer_host_id", "target_agent_id", "grant_id?", "expires_at", "max_message_bytes", "max_messages", "action") {
			return
		}
		route, err := store.CreateOutboundRoute(r.Context(), req)
		respond(w, 201, route, err)
	})
	mux.HandleFunc("GET /v1/adapters/{id}/routes", func(w http.ResponseWriter, r *http.Request) {
		routes, err := store.OutboundRoutes(r.Context(), r.PathValue("id"))
		respond(w, 200, routes, err)
	})
	mux.HandleFunc("POST /v1/adapter-routes/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		route, err := store.RevokeOutboundRoute(r.Context(), r.PathValue("id"))
		respond(w, 200, route, err)
	})
}
