// Package hideme drives hide.me through its official Linux client
// (github.com/eventure/hide.client.linux), run in service mode by the
// image's hideme.service unit. The client does hide.me's WireGuard key
// exchange over its REST API, sets up the interface, routes and DNS,
// and exposes a control API on a UNIX socket; this package only tells
// it which server to use and when.
//
// The service is started with leak protection off, IPv4 only and the
// cluster CIDR split out of the tunnel (docker/providers/hideme/
// hideme-service.sh): with the kill switch on, the pod would drop its
// own probe and control traffic every time the tunnel is down between
// two connects. The runtime's exit-ip check covers leaks instead, as
// for every other provider.
//
// Login exchanges the account login for an Access-Token, which the
// service reads from a file and refreshes by itself when hide.me marks
// it stale. The token is kept for the life of the container, so a pod
// logs in once per container start.
package hideme

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	name = "hideme"
	// controlSocket must match hideme-service.sh.
	controlSocket = "/run/hide.me/hide.me.sock"
	// serviceWait bounds how long Login waits for the service socket
	// after boot.
	serviceWait = 60 * time.Second
	// connectTimeout bounds one connect, the service's own REST timeout
	// (20 s, see hideme-service.sh) included.
	connectTimeout = 60 * time.Second
)

// HideMe implements provider.VPNProvider.
type HideMe struct{}

// tokenFile must match hideme-service.sh (a variable for the tests).
var tokenFile = "/var/lib/hideme/accessToken.txt"

var (
	mu       sync.Mutex
	client   = newControlClient(controlSocket)
	active   *server
	loggedIn bool
)

func init() {
	provider.Registry[name] = HideMe{}
}

func credentials() (username, password string, err error) {
	acct, err := accounts.Current(name)
	if err != nil {
		return "", "", err
	}
	if username, err = acct.Require(accounts.FieldUsername); err != nil {
		return "", "", err
	}
	if password, err = acct.Require(accounts.FieldPassword); err != nil {
		return "", "", err
	}
	return username, password, nil
}

// waitForService waits until the control socket answers.
func waitForService(ctx context.Context) error {
	deadline := time.Now().Add(serviceWait)
	for {
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := client.state(callCtx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("hide.me service not answering on %s: %w", controlSocket, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// isCredentialRejection reports whether err is hide.me refusing the
// account (login or token) rather than a network or server fault.
func isCredentialRejection(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "bad HTTP status 401") ||
		strings.Contains(msg, "bad HTTP status 402") ||
		strings.Contains(msg, "bad HTTP status 403")
}

func readToken() string {
	b, err := os.ReadFile(tokenFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func writeToken(token string) error {
	if err := os.MkdirAll(filepath.Dir(tokenFile), 0o700); err != nil {
		return err
	}
	tmp := tokenFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(token), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, tokenFile)
}

func (HideMe) Login(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	if err := waitForService(ctx); err != nil {
		return err
	}
	// A tunnel left by an earlier tundler-tunnel process in the same
	// container is the runtime's to replace: start from a clean client.
	if code, err := client.state(ctx); err == nil && code != "clean" && code != "routed" {
		_ = client.disconnect(ctx)
	}
	if readToken() != "" {
		loggedIn = true
		return nil
	}
	username, password, err := credentials()
	if err != nil {
		return err
	}
	servers, err := loadCatalog()
	if err != nil {
		return err
	}
	// Any server issues a token valid on all of them.
	host := servers[rand.Intn(len(servers))].Hostname
	token, err := client.requestToken(ctx, host, username, password)
	if err != nil {
		if isCredentialRejection(err) {
			return fmt.Errorf("hide.me rejected the account login: %w", err)
		}
		return fmt.Errorf("hide.me token request via %s: %w", host, err)
	}
	if token == "" {
		return errors.New("hide.me token request returned an empty token")
	}
	if err := writeToken(token); err != nil {
		return fmt.Errorf("store the hide.me token: %w", err)
	}
	// The service reads the token file when it sets up the interface,
	// so drop a set-up made before the token existed.
	_ = client.destroy(ctx)
	loggedIn = true
	return nil
}

func (HideMe) Logout(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	_ = client.destroy(ctx)
	_ = os.Remove(tokenFile)
	loggedIn = false
	active = nil
	return nil
}

func (HideMe) LoggedIn(ctx context.Context) bool {
	mu.Lock()
	defer mu.Unlock()
	return loggedIn && readToken() != ""
}

func (HideMe) Locations(ctx context.Context) []string {
	servers, err := loadCatalog()
	if err != nil {
		shared.Debugf("hide.me: %v", err)
		return nil
	}
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		out = append(out, s.Name)
	}
	return out
}

func (h HideMe) Connect(ctx context.Context, location string) provider.Status {
	servers, err := loadCatalog()
	if err != nil {
		shared.Debugf("hide.me: %v", err)
		return provider.Status{Provider: name, Location: location}
	}
	var srv server
	if location == "" {
		srv = servers[rand.Intn(len(servers))]
	} else if s, ok := findServer(servers, location); ok {
		srv = s
	} else {
		shared.Debugf("hide.me: unknown location %q", location)
		return provider.Status{Provider: name, Location: location}
	}

	mu.Lock()
	defer mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	// Leave the current server first: the service connects only from
	// the routed state.
	_ = client.disconnect(ctx)
	active = nil
	if err := client.setHost(ctx, srv.Hostname); err != nil {
		shared.Debugf("hide.me: set host %s: %v", srv.Hostname, err)
		return provider.Status{Provider: name, Location: srv.Name}
	}
	if err := client.connect(ctx); err != nil {
		shared.Debugf("hide.me: connect to %s: %v", srv.Hostname, err)
		if isCredentialRejection(err) {
			// The token no longer works: forget it so the next Login
			// asks for a new one.
			_ = os.Remove(tokenFile)
			loggedIn = false
			return provider.Status{Provider: name, Location: srv.Name, AuthFailed: true}
		}
		return provider.Status{Provider: name, Location: srv.Name}
	}
	active = &srv
	return provider.Status{
		Connected: true,
		Location:  srv.Name,
		Region:    region(srv),
		Provider:  name,
	}
}

func (HideMe) Connected(ctx context.Context) bool {
	code, err := client.state(ctx)
	return err == nil && code == "connected"
}

func (HideMe) Disconnect(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	active = nil
	return client.disconnect(ctx)
}

func (HideMe) ActiveLocation(ctx context.Context) string {
	mu.Lock()
	defer mu.Unlock()
	if active == nil {
		return ""
	}
	return active.Name
}

func (h HideMe) Status(ctx context.Context) provider.Status {
	if !h.Connected(ctx) {
		return provider.Status{Provider: name}
	}
	mu.Lock()
	defer mu.Unlock()
	st := provider.Status{Connected: true, Provider: name}
	if active != nil {
		st.Location = active.Name
		st.Region = region(*active)
	}
	return st
}

func (HideMe) Version(ctx context.Context) (string, error) {
	return client.version(ctx)
}

func region(s server) string {
	if s.City != "" {
		return s.Country + " - " + s.City
	}
	return s.Country
}
