package plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"
)

type testPlugin struct {
	meta      Metadata
	lastEvent Event
	events    []Event
}

func (p *testPlugin) Metadata() Metadata {
	return p.meta
}

func (p *testPlugin) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("root:" + r.URL.Path))
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong:" + r.URL.Path))
	})
}

func (p *testPlugin) OnEvent(_ context.Context, event Event) error {
	p.lastEvent = event
	p.events = append(p.events, event)
	return nil
}

func withRegistry(t *testing.T, registry map[string]Plugin) {
	t.Helper()
	prev := Registry
	Registry = registry
	t.Cleanup(func() {
		Registry = prev
	})
}

func TestValidatePluginRejectsInvalidMetadata(t *testing.T) {
	t.Run("nil plugin", func(t *testing.T) {
		_, err := validatePlugin("vpnipobserver", nil)
		if err == nil {
			t.Fatal("expected error for nil plugin")
		}
	})

	t.Run("empty id", func(t *testing.T) {
		_, err := validatePlugin("vpnipobserver", &testPlugin{meta: Metadata{Name: "VPN IP Observer"}})
		if err == nil {
			t.Fatal("expected error for empty id")
		}
	})

	t.Run("empty name", func(t *testing.T) {
		_, err := validatePlugin("vpnipobserver", &testPlugin{meta: Metadata{ID: "vpnipobserver"}})
		if err == nil {
			t.Fatal("expected error for empty name")
		}
	})

	t.Run("mismatched id", func(t *testing.T) {
		_, err := validatePlugin("vpnipobserver", &testPlugin{meta: Metadata{ID: "other", Name: "Other"}})
		if err == nil {
			t.Fatal("expected error for mismatched id")
		}
	})
}

func TestNewRejectsDuplicateEnabledPluginIDs(t *testing.T) {
	withRegistry(t, map[string]Plugin{
		"vpnipobserver": &testPlugin{meta: Metadata{ID: "vpnipobserver", Name: "VPN IP Observer"}},
	})

	_, err := New([]string{"vpnipobserver", "vpnipobserver"})
	if err == nil {
		t.Fatal("expected duplicate enabled plugin error")
	}
}

func TestNewLoadsSelectedPlugins(t *testing.T) {
	withRegistry(t, map[string]Plugin{
		"vpnipobserver": &testPlugin{meta: Metadata{ID: "vpnipobserver", Name: "VPN IP Observer"}},
		"auditlog":      &testPlugin{meta: Metadata{ID: "auditlog", Name: "Audit Log"}},
	})

	mgr, err := New([]string{"vpnipobserver"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	got := mgr.List()
	want := []Metadata{{ID: "vpnipobserver", Name: "VPN IP Observer"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected metadata list: got %#v want %#v", got, want)
	}
}

func TestListReturnsSortedMetadata(t *testing.T) {
	withRegistry(t, map[string]Plugin{
		"zeta":  &testPlugin{meta: Metadata{ID: "zeta", Name: "Zeta"}},
		"alpha": &testPlugin{meta: Metadata{ID: "alpha", Name: "Alpha"}},
	})

	mgr, err := New(nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	got := mgr.List()
	ids := []string{got[0].ID, got[1].ID}
	if !slices.Equal(ids, []string{"alpha", "zeta"}) {
		t.Fatalf("unexpected metadata order: %v", ids)
	}
}

func TestEmitDeliversConnectionAndDisconnectionEvents(t *testing.T) {
	first := &testPlugin{meta: Metadata{ID: "alpha", Name: "Alpha"}}
	second := &testPlugin{meta: Metadata{ID: "beta", Name: "Beta"}}
	withRegistry(t, map[string]Plugin{
		"alpha": first,
		"beta":  second,
	})

	mgr, err := New(nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	before := time.Now().UTC()
	mgr.Emit(context.Background(), "connected", "nordvpn", "Paris", "France", "1.2.3.4")
	mgr.Emit(context.Background(), "disconnected", "nordvpn", "Paris", "France", "1.2.3.4")
	after := time.Now().UTC()

	for _, plug := range []*testPlugin{first, second} {
		if len(plug.events) != 2 {
			t.Fatalf("unexpected event count: %d", len(plug.events))
		}
		if plug.events[0].Type != "connected" || plug.events[1].Type != "disconnected" {
			t.Fatalf("unexpected event types: %#v", plug.events)
		}
		if plug.events[0].Provider != "nordvpn" || plug.events[0].Region != "France" || plug.events[0].Location != "Paris" || plug.events[0].IP != "1.2.3.4" {
			t.Fatalf("unexpected connected event payload: %#v", plug.events[0])
		}
		if plug.events[0].Timestamp.Before(before) || plug.events[0].Timestamp.After(after) {
			t.Fatalf("connected timestamp out of range: %v", plug.events[0].Timestamp)
		}
	}
}

func TestMountRoutesPluginRootAndSubpaths(t *testing.T) {
	withRegistry(t, map[string]Plugin{
		"vpnipobserver": &testPlugin{meta: Metadata{ID: "vpnipobserver", Name: "VPN IP Observer"}},
	})

	mgr, err := New(nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	mux := http.NewServeMux()
	mgr.Mount(mux)

	rootReq := httptest.NewRequest(http.MethodGet, "/plugins/vpnipobserver", nil)
	rootRec := httptest.NewRecorder()
	mux.ServeHTTP(rootRec, rootReq)
	if body := rootRec.Body.String(); body != "root:/" {
		t.Fatalf("unexpected root response: %q", body)
	}

	pingReq := httptest.NewRequest(http.MethodGet, "/plugins/vpnipobserver/ping", nil)
	pingRec := httptest.NewRecorder()
	mux.ServeHTTP(pingRec, pingReq)
	if body := pingRec.Body.String(); body != "pong:/ping" {
		t.Fatalf("unexpected subpath response: %q", body)
	}
}
