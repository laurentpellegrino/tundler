package httpapi

import (
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
	"strings"

	"github.com/laurentpellegrino/tundler/internal/manager"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

func Router(mgr *manager.Manager) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, mgr.List(r.Context()))
	})

	mux.HandleFunc("/locations", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, mgr.Locations(r.Context()))
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		provs := r.URL.Query().Get("providers")
		if provs == "" {
			if err := mgr.Login(r.Context(), ""); err != nil {
				writeErr(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		for _, name := range strings.Split(provs, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if err := mgr.Login(r.Context(), name); err != nil {
				writeErr(w, err)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		provs := parseCSV(r.URL.Query().Get("providers"))
		if len(provs) == 0 {
			if err := mgr.Logout(r.Context(), ""); err != nil {
				writeErr(w, err)
				return
			}
		} else {
			for _, prov := range provs {
				if err := mgr.Logout(r.Context(), prov); err != nil {
					writeErr(w, err)
					return
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		prov := pickRandom(parseCSV(r.URL.Query().Get("providers")))
		loc := pickRandom(parseCSV(r.URL.Query().Get("locations")))
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

func parseCSV(s string) []string {
	var result []string
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			result = append(result, v)
		}
	}
	return result
}

func pickRandom(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[rand.Intn(len(list))]
}
