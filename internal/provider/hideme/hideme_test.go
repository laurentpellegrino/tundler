package hideme

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const sampleCatalog = `[
 {"hostname":"al-v4.hideservers.net","displayName":"Albania","tags":["upgrade"],"geo":{"cityName":"Tirana","countryCode":"AL"}},
 {"hostname":"fi2-v4.hideservers.net","displayName":"Finland","geo":{"countryCode":"FI"},"children":[
   {"hostname":"fi1-v4.hideservers.net","displayName":"Helsinki #1","geo":{"cityName":"Helsinki","countryCode":"FI"}},
   {"hostname":"fi2-v4.hideservers.net","displayName":"Helsinki #2","geo":{"cityName":"Helsinki","countryCode":"FI"}}]},
 {"hostname":"us-v4.hideservers.net","displayName":"United States","geo":{"countryCode":"US"},"children":[
   {"hostname":"washington-dc-v4.hideservers.net","displayName":"Washington, D.C.","geo":{"cityName":"Washington","countryCode":"US"}},
   {"hostname":"seattle-v4.hideservers.net","displayName":"Washington, Seattle","geo":{"cityName":"Seattle"}}]},
 {"hostname":"free-uk-v4.hideservers.net","displayName":"United Kingdom - Free","tags":["free"],"geo":{"cityName":"London","countryCode":"GB"}},
 {"hostname":"br-v4.hideservers.net","displayName":"Brasil","geo":{"cityName":"São Paulo","countryCode":"BR"}},
 {"hostname":"br2-v4.hideservers.net","displayName":"Brasil","geo":{"cityName":"Rio","countryCode":"BR"}},
 {"hostname":"","displayName":"broken","geo":{"countryCode":"XX"}}
]`

func TestParseCatalogNamesLeafServers(t *testing.T) {
	servers, err := parseCatalog([]byte(sampleCatalog))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range servers {
		got[s.Name] = s.Hostname
	}
	want := map[string]string{
		"al":                    "al-v4.hideservers.net",
		"fi-helsinki-1":         "fi1-v4.hideservers.net",
		"fi-helsinki-2":         "fi2-v4.hideservers.net",
		"us-washington-d-c":     "washington-dc-v4.hideservers.net",
		"us-washington-seattle": "seattle-v4.hideservers.net",
		"gb-free":               "free-uk-v4.hideservers.net",
		"br":                    "br-v4.hideservers.net",
		"br-2":                  "br2-v4.hideservers.net",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for n, h := range want {
		if got[n] != h {
			t.Errorf("location %s: got host %q, want %q", n, got[n], h)
		}
	}
	for _, s := range servers {
		if s.Name == "us-washington-seattle" && s.Country != "US" {
			t.Errorf("child without a country code should inherit the parent's, got %q", s.Country)
		}
	}
}

func TestParseCatalogRejectsAnEmptyList(t *testing.T) {
	if _, err := parseCatalog([]byte(`[]`)); err == nil {
		t.Fatal("want an error for an empty list")
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Helsinki #1":             "helsinki-1",
		"New York, New York City": "new-york-new-york-city",
		"  Zug ":                  "zug",
		"São Paulo":               "são-paulo",
		"":                        "",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeService mimics the control API of `hide.me service`.
type fakeService struct {
	mu          sync.Mutex
	state       string
	host        string
	tokenErr    string
	connectErr  string
	tokenCalls  int
	configBody  []string
	tokenLogins []string
}

func (f *fakeService) handler() http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		reply(w, map[string]any{"result": map[string]string{"code": f.state}})
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("0.9.15")) })
	mux.HandleFunc("/requestToken", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokenCalls++
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.tokenLogins = append(f.tokenLogins, body["Username"]+"/"+body["Password"]+"@"+body["Host"])
		if f.tokenErr != "" {
			reply(w, map[string]any{"error": map[string]string{"code": "token", "message": f.tokenErr}})
			return
		}
		reply(w, map[string]any{"result": "dG9rZW4="})
	})
	mux.HandleFunc("/configuration", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body struct{ Rest map[string]string }
		raw := new(strings.Builder)
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(raw).Encode(body)
		f.configBody = append(f.configBody, raw.String())
		f.host = body.Rest["Host"]
		reply(w, map[string]any{"result": true})
	})
	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.connectErr != "" {
			f.state = "routed"
			reply(w, map[string]any{"error": map[string]string{"code": "connect", "message": f.connectErr}})
			return
		}
		f.state = "connected"
		reply(w, map[string]any{"result": map[string]string{"code": "connected"}})
	})
	mux.HandleFunc("/disconnect", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.state == "connected" {
			f.state = "routed"
		}
		reply(w, map[string]any{"result": map[string]string{"code": f.state}})
	})
	mux.HandleFunc("/destroy", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.state = "clean"
		reply(w, map[string]any{"result": map[string]string{"code": "clean"}})
	})
	return mux
}

// startFake serves a fakeService on a UNIX socket and points the
// package at it, a temporary token file and the sample catalog.
func startFake(t *testing.T) *fakeService {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "hide.me.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeService{state: "clean"}
	srv := &http.Server{Handler: f.handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	servers, err := parseCatalog([]byte(sampleCatalog))
	if err != nil {
		t.Fatal(err)
	}
	oldClient, oldToken := client, tokenFile
	catalogMu.Lock()
	oldCatalog := catalogCache
	catalogCache = servers
	catalogMu.Unlock()
	client = newControlClient(sock)
	tokenFile = filepath.Join(dir, "state", "accessToken.txt")
	loggedIn, active = false, nil
	t.Cleanup(func() {
		client, tokenFile = oldClient, oldToken
		catalogMu.Lock()
		catalogCache = oldCatalog
		catalogMu.Unlock()
		loggedIn, active = false, nil
	})
	t.Setenv("TUNDLER_ACCOUNT_USERNAME", "user")
	t.Setenv("TUNDLER_ACCOUNT_PASSWORD", "secret")
	return f
}

func TestLoginStoresTheTokenAndKeepsTheLoginOutOfTheConfiguration(t *testing.T) {
	f := startFake(t)
	h := HideMe{}
	ctx := context.Background()
	if err := h.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if !h.LoggedIn(ctx) {
		t.Fatal("want logged in")
	}
	b, err := os.ReadFile(tokenFile)
	if err != nil || string(b) != "dG9rZW4=" {
		t.Fatalf("token file %q, %v", b, err)
	}
	if info, _ := os.Stat(tokenFile); info.Mode().Perm() != 0o600 {
		t.Errorf("token file mode %v, want 0600", info.Mode().Perm())
	}
	if f.tokenCalls != 1 || !strings.HasPrefix(f.tokenLogins[0], "user/secret@") {
		t.Fatalf("token requests %v", f.tokenLogins)
	}
	// A second Login reuses the stored token.
	if err := h.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if f.tokenCalls != 1 {
		t.Fatalf("token requested %d times, want 1", f.tokenCalls)
	}
	if st := h.Connect(ctx, "al"); !st.Connected {
		t.Fatalf("connect: %+v", st)
	}
	for _, body := range f.configBody {
		if strings.Contains(body, "secret") || strings.Contains(body, "dG9rZW4=") {
			t.Fatalf("a configuration request carried a secret: %s", body)
		}
	}
}

func TestLoginReportsARejectedAccount(t *testing.T) {
	f := startFake(t)
	f.tokenErr = "bad HTTP status 401"
	err := HideMe{}.Login(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rejected the account login") {
		t.Fatalf("err %v", err)
	}
	if (HideMe{}).LoggedIn(context.Background()) {
		t.Fatal("want logged out")
	}
}

func TestConnectSwitchesServerAndReportsTheLocation(t *testing.T) {
	f := startFake(t)
	h := HideMe{}
	ctx := context.Background()
	if err := h.Login(ctx); err != nil {
		t.Fatal(err)
	}
	st := h.Connect(ctx, "fi-helsinki-1")
	if !st.Connected || st.Location != "fi-helsinki-1" || st.Region != "FI - Helsinki" {
		t.Fatalf("status %+v", st)
	}
	if f.host != "fi1-v4.hideservers.net" {
		t.Fatalf("host %q", f.host)
	}
	if !h.Connected(ctx) || h.ActiveLocation(ctx) != "fi-helsinki-1" {
		t.Fatal("want connected at fi-helsinki-1")
	}
	st = h.Connect(ctx, "gb-free")
	if !st.Connected || f.host != "free-uk-v4.hideservers.net" {
		t.Fatalf("second connect %+v host %q", st, f.host)
	}
	if err := h.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Connected(ctx) || h.ActiveLocation(ctx) != "" {
		t.Fatal("want disconnected")
	}
}

func TestConnectToAnUnknownLocationFails(t *testing.T) {
	startFake(t)
	if st := (HideMe{}).Connect(context.Background(), "atlantis"); st.Connected {
		t.Fatalf("status %+v", st)
	}
}

func TestConnectWithARejectedTokenMarksAuthFailedAndForgetsTheToken(t *testing.T) {
	f := startFake(t)
	h := HideMe{}
	ctx := context.Background()
	if err := h.Login(ctx); err != nil {
		t.Fatal(err)
	}
	f.connectErr = "bad HTTP status 401"
	st := h.Connect(ctx, "al")
	if st.Connected || !st.AuthFailed {
		t.Fatalf("status %+v", st)
	}
	if h.LoggedIn(ctx) {
		t.Fatal("want logged out after a rejected token")
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Fatalf("token file still there: %v", err)
	}
}

func TestConnectFailureIsNotAnAuthFailure(t *testing.T) {
	f := startFake(t)
	h := HideMe{}
	ctx := context.Background()
	if err := h.Login(ctx); err != nil {
		t.Fatal(err)
	}
	f.connectErr = "lookup al-v4.hideservers.net: no such host"
	st := h.Connect(ctx, "al")
	if st.Connected || st.AuthFailed {
		t.Fatalf("status %+v", st)
	}
	if !h.LoggedIn(ctx) {
		t.Fatal("a network failure must keep the token")
	}
}

func TestLocationsAndVersion(t *testing.T) {
	startFake(t)
	h := HideMe{}
	locs := h.Locations(context.Background())
	if len(locs) != 8 || locs[0] != "al" {
		t.Fatalf("locations %v", locs)
	}
	if v, err := h.Version(context.Background()); err != nil || v != "0.9.15" {
		t.Fatalf("version %q, %v", v, err)
	}
}
