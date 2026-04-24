package vpnipobserver

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/plugin"
)

type observer struct {
	mu   sync.RWMutex
	seen map[string]*record
}

type record struct {
	IP        string            `json:"ip"`
	LastSeen  time.Time         `json:"last_seen"`
	Providers map[string]string `json:"providers"`
	Regions   map[string]string `json:"regions,omitempty"`
}

type response struct {
	IPs []record `json:"ips"`
}

func init() {
	plugin.Registry["vpnipobserver"] = &observer{
		seen: map[string]*record{},
	}
}

func (o *observer) Metadata() plugin.Metadata {
	return plugin.Metadata{
		ID:   "vpnipobserver",
		Name: "VPN IP Observer",
	}
}

func (o *observer) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/", o.handleList)
	mux.HandleFunc("/ips", o.handleList)
}

func (o *observer) OnEvent(_ context.Context, event plugin.Event) error {
	if event.Type != "connected" || event.IP == "" {
		return nil
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	rec, ok := o.seen[event.IP]
	if !ok {
		rec = &record{
			IP:        event.IP,
			Providers: map[string]string{},
			Regions:   map[string]string{},
		}
		o.seen[event.IP] = rec
	}

	rec.LastSeen = event.Timestamp
	rec.Providers[event.Provider] = event.Timestamp.Format(time.RFC3339)
	if event.Region != "" {
		rec.Regions[event.Provider] = event.Region
	}
	return nil
}

func (o *observer) handleList(w http.ResponseWriter, _ *http.Request) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	items := make([]record, 0, len(o.seen))
	for _, rec := range o.seen {
		item := record{
			IP:        rec.IP,
			LastSeen:  rec.LastSeen,
			Providers: make(map[string]string, len(rec.Providers)),
			Regions:   make(map[string]string, len(rec.Regions)),
		}
		for provider, seenAt := range rec.Providers {
			item.Providers[provider] = seenAt
		}
		for provider, region := range rec.Regions {
			item.Regions[provider] = region
		}
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].LastSeen.After(items[j].LastSeen)
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response{IPs: items})
}
