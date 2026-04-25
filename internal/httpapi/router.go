package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/laurentpellegrino/tundler/internal/manager"
	"github.com/laurentpellegrino/tundler/internal/plugin"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

// readyzTimeout caps how long /readyz may spend gathering provider
// status before it gives up and reports 503. Kept short so a kubelet
// readinessProbe at this path doesn't itself stall on a wedged VPN
// daemon — the whole point of having /readyz separate from /livez.
const readyzTimeout = 3 * time.Second

func Router(mgr *manager.Manager, plugins *plugin.Manager) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, mgr.List(r.Context()))
	})

	// /livez and /readyz follow the kube-apiserver split:
	//
	//   /livez  — "is the process alive?". Returns 200 as long as the
	//             HTTP server is responsive. Never touches a provider
	//             daemon. Point kubelet's livenessProbe here so a
	//             wedged VPN CLI (the recurring expressvpnd CPU-spin
	//             failure mode) can no longer take the whole tundler
	//             container down — / would have iterated every
	//             provider's daemon and stalled.
	//
	//   /readyz — "can it serve traffic?". Calls mgr.List with a short
	//             deadline and returns 503 if it can't gather provider
	//             status in time. Suitable for a kubelet
	//             readinessProbe behind a Service.
	mux.HandleFunc("/livez", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readyzTimeout)
		defer cancel()
		info := mgr.List(ctx)
		if ctx.Err() != nil {
			// At least one provider's CLI didn't respond in time —
			// mgr.List returns whatever it had filled in, but the
			// context-expired signal tells us the snapshot is
			// degraded. Don't claim "ready".
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"degraded","reason":"provider status query timed out"}`))
			return
		}
		writeJSON(w, info)
	})

	mux.HandleFunc("/locations", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, mgr.Locations(r.Context()))
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if err := forEachProvider(r, mgr.Login); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if err := forEachProvider(r, mgr.Logout); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		prov := pickRandom(parseCSV(q.Get("providers")))
		allow := parseCSV(q.Get("locations.allow"))
		block := parseCSV(q.Get("locations.block"))
		st, err := mgr.Connect(r.Context(), prov, "", allow, block)
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

	mux.HandleFunc("/plugins", func(w http.ResponseWriter, _ *http.Request) {
		if plugins == nil {
			writeJSON(w, map[string]any{"plugins": []plugin.Metadata{}})
			return
		}
		writeJSON(w, map[string]any{"plugins": plugins.List()})
	})

	if plugins != nil {
		plugins.Mount(mux)
	}
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

func forEachProvider(r *http.Request, fn func(context.Context, string) error) error {
	provs := parseCSV(r.URL.Query().Get("providers"))
	if len(provs) == 0 {
		return fn(r.Context(), "")
	}
	for _, prov := range provs {
		if err := fn(r.Context(), prov); err != nil {
			return err
		}
	}
	return nil
}
