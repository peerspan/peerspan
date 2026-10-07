package host

import (
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// artifactTransfer bounds how long one upload or download may take.
const artifactTransfer = 10 * time.Minute

// uploadArtifact stores a raw request body as an artifact upload. The name
// and optional media type come from the query string.
func uploadArtifact(w http.ResponseWriter, r *http.Request, store *Store) {
	defer r.Body.Close()
	query := r.URL.Query()
	mediaType := defaultMediaType
	if values, ok := query["media_type"]; ok {
		mediaType = values[0]
	}
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(artifactTransfer))
	_ = controller.SetWriteDeadline(time.Now().Add(artifactTransfer))
	entry, err := store.UploadArtifact(r.Context(), query.Get("name"), mediaType, r.Body)
	respond(w, http.StatusOK, entry, err)
}

// serveArtifact writes an opened artifact as application/octet-stream with
// its exact length.
func serveArtifact(w http.ResponseWriter, f *os.File, size int64, err error) {
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	defer f.Close()
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(artifactTransfer))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(w, f, size)
}

func peerArtifactRoutes(mux *http.ServeMux, store *Store, sender func(http.ResponseWriter, *http.Request) (string, bool)) {
	mux.HandleFunc("GET /peer/v1/tasks/{id}/artifacts/{sha256}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		f, size, err := store.PeerArtifact(r.Context(), id, r.PathValue("id"), r.PathValue("sha256"))
		serveArtifact(w, f, size, err)
	})
}

func localArtifactRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("POST /v1/artifacts", func(w http.ResponseWriter, r *http.Request) {
		uploadArtifact(w, r, store)
	})
	mux.HandleFunc("GET /v1/artifacts", func(w http.ResponseWriter, r *http.Request) {
		list, err := store.Artifacts(r.Context())
		respond(w, http.StatusOK, list, err)
	})
	mux.HandleFunc("POST /v1/artifacts/prune", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.PruneArtifacts(r.Context())
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("GET /v1/tasks/{peer}/{id}/artifacts/{sha256}", func(w http.ResponseWriter, r *http.Request) {
		f, size, err := store.OutboundArtifact(r.Context(), r.PathValue("peer"), r.PathValue("id"), r.PathValue("sha256"))
		serveArtifact(w, f, size, err)
	})
}

func adapterArtifactRoutes(mux *http.ServeMux, store *Store, token func(*http.Request) AdapterAuth) {
	mux.HandleFunc("POST /adapter/v1/artifacts", func(w http.ResponseWriter, r *http.Request) {
		// The credential is checked before the body is read.
		tx, err := store.db.BeginTx(r.Context(), nil)
		if err == nil {
			_, _, err = adapterAuthority(r.Context(), tx, token(r))
			_ = tx.Rollback()
		}
		if err != nil {
			respond(w, 0, nil, err)
			return
		}
		uploadArtifact(w, r, store)
	})
	mux.HandleFunc("GET /adapter/v1/delegations/{id}/artifacts/{sha256}", func(w http.ResponseWriter, r *http.Request) {
		f, size, err := store.AdapterDelegationArtifact(r.Context(), token(r), r.PathValue("id"), r.PathValue("sha256"))
		serveArtifact(w, f, size, err)
	})
	mux.HandleFunc("GET /adapter/v1/tasks/{id}/artifacts/{sha256}", func(w http.ResponseWriter, r *http.Request) {
		f, size, err := store.AdapterTaskArtifact(r.Context(), token(r), r.PathValue("id"), r.PathValue("sha256"))
		serveArtifact(w, f, size, err)
	})
}
