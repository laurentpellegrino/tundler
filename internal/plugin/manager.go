package plugin

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

type Manager struct {
	plugins map[string]Plugin
}

func New(enabled []string) (*Manager, error) {
	plugins := make(map[string]Plugin)
	seen := make(map[string]struct{})

	if len(enabled) == 0 {
		for registryID, plug := range Registry {
			meta, err := validatePlugin(registryID, plug)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[meta.ID]; ok {
				return nil, fmt.Errorf("duplicate plugin id %q", meta.ID)
			}
			seen[meta.ID] = struct{}{}
			plugins[meta.ID] = plug
		}
		return &Manager{plugins: plugins}, nil
	}

	for _, id := range enabled {
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("plugin %q enabled more than once", id)
		}
		plug, ok := Registry[id]
		if !ok {
			return nil, fmt.Errorf("unknown plugin %q", id)
		}
		meta, err := validatePlugin(id, plug)
		if err != nil {
			return nil, err
		}
		if meta.ID != id {
			return nil, fmt.Errorf("plugin %q metadata id %q does not match configured id", id, meta.ID)
		}
		seen[meta.ID] = struct{}{}
		plugins[meta.ID] = plug
	}
	return &Manager{plugins: plugins}, nil
}

func (m *Manager) metadataList() []Metadata {
	items := make([]Metadata, 0, len(m.plugins))
	for _, plug := range m.plugins {
		items = append(items, plug.Metadata())
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})
	return items
}

func (m *Manager) List() []Metadata {
	return m.metadataList()
}

func (m *Manager) Mount(mux *http.ServeMux) {
	for _, meta := range m.metadataList() {
		prefix := "/plugins/" + meta.ID
		sub := http.NewServeMux()
		m.plugins[meta.ID].Mount(sub)
		mux.Handle(prefix+"/", http.StripPrefix(prefix, sub))
		mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			sub.ServeHTTP(w, r2)
		})
	}
}

func (m *Manager) Emit(ctx context.Context, typ, provider, location, region, ip string) {
	event := Event{
		Type:      typ,
		Provider:  provider,
		Location:  location,
		Region:    region,
		IP:        ip,
		Timestamp: time.Now().UTC(),
	}
	for _, meta := range m.metadataList() {
		if err := m.plugins[meta.ID].OnEvent(ctx, event); err != nil {
			log.Printf("[plugin:%s] event hook failed: %v", meta.ID, err)
		}
	}
}

func validatePlugin(registryID string, plug Plugin) (Metadata, error) {
	if plug == nil {
		return Metadata{}, fmt.Errorf("plugin %q is nil", registryID)
	}

	meta := plug.Metadata()
	meta.ID = strings.TrimSpace(meta.ID)
	meta.Name = strings.TrimSpace(meta.Name)

	if meta.ID == "" {
		return Metadata{}, fmt.Errorf("plugin %q has empty metadata id", registryID)
	}
	if meta.Name == "" {
		return Metadata{}, fmt.Errorf("plugin %q has empty metadata name", registryID)
	}
	if registryID != "" && meta.ID != registryID {
		return Metadata{}, fmt.Errorf("plugin registry key %q does not match metadata id %q", registryID, meta.ID)
	}

	return meta, nil
}
