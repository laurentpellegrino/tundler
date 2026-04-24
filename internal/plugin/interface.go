package plugin

import (
	"context"
	"net/http"
	"time"
)

type Metadata struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Event is emitted after tunnel lifecycle changes.
type Event struct {
	Type      string    `json:"type"`
	Provider  string    `json:"provider"`
	Location  string    `json:"location,omitempty"`
	Region    string    `json:"region,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Plugin is an optional sidecar extension point for non-core features.
type Plugin interface {
	Metadata() Metadata
	Mount(*http.ServeMux)
	OnEvent(context.Context, Event) error
}

// Registry is filled at init() time by plugin packages.
var Registry = map[string]Plugin{}
