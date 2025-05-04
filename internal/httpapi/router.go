package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/laurentpellegrino/tundler/internal/manager"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

func Router(mgr *manager.Manager) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, mgr.List(r.Context()))
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		prov := r.URL.Query().Get("provider")
		if err := mgr.Login(r.Context(), prov); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		prov := r.URL.Query().Get("provider")
		if err := mgr.Logout(r.Context(), prov); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		prov := r.URL.Query().Get("provider") // optional
		loc := r.URL.Query().Get("location")  // optional
		st, err := mgr.Connect(r.Context(), prov, loc)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, st)
	})

	mux.HandleFunc("/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Disconnect(r.Context()); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := mgr.Status(r.Context())
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, st)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var appErr shared.Error
	if errors.As(err, &appErr) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.Status)
		_ = json.NewEncoder(w).Encode(appErr)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
