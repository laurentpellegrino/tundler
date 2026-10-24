// Package hidemyass uses HMA's native account and SurfEasy device APIs and
// discovers OpenVPN endpoints at runtime, without a bundled profile archive.
package hidemyass

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	"github.com/laurentpellegrino/tundler/internal/geo"
	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const name = "hidemyass"

type HideMyAss struct{}
type activeConnection struct {
	VIP      string
	Tunnel   *openVPNTunnel
	Location string
	Country  string
	Server   vpnServer
}

var hmaState struct {
	conns     map[*tunnelConn]bool
	op        sync.Mutex
	mu        sync.RWMutex
	device    savedDevice
	backend   *backendClient
	countries []locationCountry
	loggedIn  bool
	active    *activeConnection
	cleanup   *activeConnection
}

func init() {
	provider.Registry[name] = HideMyAss{}
	accounts.RegisterLegacyShim(name, accounts.LegacyEnvFields(map[string]string{
		accounts.FieldUsername: "HIDEMYASS_USERNAME", accounts.FieldPassword: "HIDEMYASS_PASSWORD",
	}))
}

func credentialsFromAccount() (string, string, error) {
	account, err := accounts.Current(name)
	if err != nil {
		return "", "", err
	}
	user, err := account.Require(accounts.FieldUsername)
	if err != nil {
		return "", "", err
	}
	password, err := account.Require(accounts.FieldPassword)
	if err != nil {
		return "", "", err
	}
	return user, password, nil
}

func login(ctx context.Context) (result error) {
	defer func() {
		if result != nil {
			hmaState.mu.Lock()
			hmaState.loggedIn = false
			hmaState.mu.Unlock()
		}
	}()
	if err := ensurePrivateDirectory(stateDir()); err != nil {
		return err
	}
	user, password, err := credentialsFromAccount()
	if err != nil {
		return err
	}
	hash := accountHash(user, password)
	fingerprint := deviceFingerprint(user)
	saved, found := loadDevice(stateDir(), hash, fingerprint)
	backend := newBackendClient()
	var countries []locationCountry
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 || !found || !saved.Session.valid(time.Now()) {
			account, err := newAccountClient(fingerprint)
			if err != nil {
				return err
			}
			session, err := account.login(ctx, user, password)
			if err != nil {
				return err
			}
			licenses, err := account.licenses(ctx, session)
			if err != nil {
				return err
			}
			license, err := selectLicense(licenses, time.Now())
			if err != nil {
				return err
			}
			device, err := backend.associate(ctx, license, fingerprint)
			if err != nil {
				return err
			}
			// Renewing tokens for the same fingerprint reuses its credentials and slot.
			if saved.Credentials.DeviceUDID != device.UDID {
				saved.Credentials = vpnCredentials{}
			}
			saved.Session = device
			saved.AccountHash = hash
			saved.Fingerprint = fingerprint
		}
		if saved.Credentials.DevicePassword == "" || saved.Credentials.OpenVPNCA == "" {
			saved.Credentials, err = backend.credentials(ctx, saved.Session)
			if err != nil && !(attempt == 0 && errors.Is(err, errSessionExpired)) {
				return err
			}
		}
		if attempt == 0 && errors.Is(err, errSessionExpired) {
			continue
		}
		countries, err = backend.locations(ctx, saved.Session)
		if err != nil {
			if attempt == 0 && errors.Is(err, errSessionExpired) {
				continue
			}
			return err
		}
		break
	}
	if err := saveDevice(stateDir(), saved); err != nil {
		return err
	}
	hmaState.mu.Lock()
	hmaState.device = saved
	hmaState.backend = backend
	hmaState.countries = countries
	hmaState.loggedIn = true
	hmaState.mu.Unlock()
	return nil
}

func (HideMyAss) Login(ctx context.Context) error {
	hmaState.op.Lock()
	defer hmaState.op.Unlock()
	return login(ctx)
}

// Only a server's explicit authentication rejection triggers credential
// reissuance. Network or certificate errors must not repeatedly rotate devices.
func refreshDeviceCredentials(ctx context.Context) (savedDevice, error) {
	for attempt := 0; attempt < 2; attempt++ {
		hmaState.mu.RLock()
		saved, backend := hmaState.device, hmaState.backend
		hmaState.mu.RUnlock()
		creds, err := backend.credentials(ctx, saved.Session)
		if attempt == 0 && errors.Is(err, errSessionExpired) {
			if err := login(ctx); err != nil {
				return savedDevice{}, err
			}
			continue
		}
		if err != nil {
			return savedDevice{}, err
		}
		saved.Credentials = creds
		if err := saveDevice(stateDir(), saved); err != nil {
			return savedDevice{}, err
		}
		hmaState.mu.Lock()
		hmaState.device = saved
		hmaState.mu.Unlock()
		return saved, nil
	}
	return savedDevice{}, errSessionExpired
}

func (HideMyAss) LoggedIn(context.Context) bool {
	hmaState.mu.RLock()
	defer hmaState.mu.RUnlock()
	return hmaState.loggedIn && hmaState.device.Session.valid(time.Now())
}

func (HideMyAss) Logout(context.Context) error {
	hmaState.op.Lock()
	defer hmaState.op.Unlock()
	if err := os.Remove(filepath.Join(stateDir(), "device.json")); err != nil && !os.IsNotExist(err) {
		return errors.New("remove HMA device session")
	}
	hmaState.mu.Lock()
	hmaState.loggedIn = false
	hmaState.device = savedDevice{}
	hmaState.mu.Unlock()
	return nil
}

func countryName(c locationCountry) string {
	if canonical, ok := geo.CountryName(strings.ToUpper(c.CC)); ok {
		return canonical
	}
	return c.Country
}

func (HideMyAss) Locations(context.Context) []string {
	hmaState.mu.RLock()
	defer hmaState.mu.RUnlock()
	seen := map[string]bool{}
	var locations []string
	for _, c := range hmaState.countries {
		country := countryName(c)
		if supportedLocation(c) && country != "" && !seen[country] {
			seen[country] = true
			locations = append(locations, country)
		}
	}
	sort.Strings(locations)
	return locations
}

func locationKeys(countries []locationCountry, want string) []struct{ Key, Country string } {
	want = strings.TrimSpace(want)
	var keys []struct{ Key, Country string }
	for _, c := range countries {
		if !supportedLocation(c) {
			continue
		}
		country := countryName(c)
		countryMatch := want == "" || strings.EqualFold(want, country) || strings.EqualFold(want, c.Country) || strings.EqualFold(want, c.CC) || strings.EqualFold(want, c.Key)
		for _, city := range c.Cities {
			if !strings.EqualFold(city.State, "active") || city.Key == "" {
				continue
			}
			if countryMatch || strings.EqualFold(want, city.City) || strings.EqualFold(want, city.Key) {
				keys = append(keys, struct{ Key, Country string }{city.Key, country})
			}
		}
		if countryMatch && len(c.Cities) == 0 {
			keys = append(keys, struct{ Key, Country string }{c.Key, country})
		}
	}
	return keys
}

func (h HideMyAss) Connect(ctx context.Context, location string) provider.Status {
	hmaState.op.Lock()
	defer hmaState.op.Unlock()
	failed := provider.Status{Provider: name, Location: location}
	if err := disconnect(ctx); err != nil {
		shared.Debugf("HideMyAss: disconnect: %v", err)
		return failed
	}
	if !h.LoggedIn(ctx) {
		if err := login(ctx); err != nil {
			shared.Debugf("HideMyAss: login: %v", err)
			return failed
		}
	}
	hmaState.mu.RLock()
	keys := locationKeys(hmaState.countries, location)
	backend := hmaState.backend
	saved := hmaState.device
	hmaState.mu.RUnlock()
	if len(keys) == 0 {
		shared.Debugf("HideMyAss: no active location matches %q", location)
		return failed
	}
	choice := keys[rand.Intn(len(keys))]
	servers, err := backend.servers(ctx, saved.Session, choice.Key)
	if errors.Is(err, errSessionExpired) {
		if err = login(ctx); err == nil {
			hmaState.mu.RLock()
			saved, backend = hmaState.device, hmaState.backend
			hmaState.mu.RUnlock()
			servers, err = backend.servers(ctx, saved.Session, choice.Key)
		}
	}
	if err != nil {
		shared.Debugf("HideMyAss: server discovery: %v", err)
		return failed
	}

	// Try a bounded set of candidates under the caller's cancellation deadline.
	rand.Shuffle(len(servers), func(i, j int) { servers[i], servers[j] = servers[j], servers[i] })
	refreshedCredentials := false
	for i, server := range servers {
		if i >= 3 || ctx.Err() != nil {
			break
		}
		tunnel, err := startTunnel(ctx, stateDir(), server, saved.Credentials)
		if errors.Is(err, errTransportAuthentication) && !refreshedCredentials {
			refreshedCredentials = true
			if saved, err = refreshDeviceCredentials(ctx); err == nil {
				tunnel, err = startTunnel(ctx, stateDir(), server, saved.Credentials)
			} else {
				shared.Debugf("HideMyAss: refresh device credentials: %v", err)
				return failed
			}
		}
		if err != nil {
			shared.Debugf("HideMyAss: OpenVPN connection: %v", err)
			continue
		}

		activeLocation := location
		if activeLocation == "" {
			activeLocation = choice.Country
		}
		candidate := &activeConnection{Location: activeLocation, Country: choice.Country, Server: server, VIP: tunnel.address(), Tunnel: tunnel}
		hmaState.mu.Lock()
		hmaState.cleanup = candidate
		hmaState.mu.Unlock()
		if err := policyRule(ctx, candidate.VIP, true); err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
			_ = disconnect(cleanup)
			cancel()
			shared.Debugf("HideMyAss: %v", err)
			return failed
		}
		hmaState.mu.Lock()
		hmaState.active, hmaState.cleanup = candidate, nil
		hmaState.mu.Unlock()
		return h.Status(ctx)
	}
	return failed
}

func disconnect(ctx context.Context) error {
	hmaState.mu.Lock()
	active := hmaState.active
	if active == nil {
		active = hmaState.cleanup
	}
	hmaState.active = nil
	hmaState.cleanup = active
	conns := make([]*tunnelConn, 0, len(hmaState.conns))
	for conn := range hmaState.conns {
		conns = append(conns, conn)
	}
	hmaState.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	if active != nil {
		if err := active.Tunnel.stop(ctx); err != nil {
			return err
		}
		if active.VIP != "" {
			if err := policyRule(ctx, active.VIP, false); err != nil {
				return err
			}
		}
	}
	hmaState.mu.Lock()
	hmaState.cleanup = nil
	hmaState.mu.Unlock()
	return nil
}

func (HideMyAss) Disconnect(ctx context.Context) error {
	hmaState.op.Lock()
	defer hmaState.op.Unlock()
	return disconnect(ctx)
}

func (HideMyAss) Connected(ctx context.Context) bool {
	hmaState.mu.RLock()
	active := hmaState.active
	hmaState.mu.RUnlock()
	return active != nil && active.VIP != "" && active.Tunnel != nil && active.VIP == active.Tunnel.address()
}

func (h HideMyAss) ActiveLocation(ctx context.Context) string {
	if !h.Connected(ctx) {
		return ""
	}
	hmaState.mu.RLock()
	defer hmaState.mu.RUnlock()
	if hmaState.active == nil {
		return ""
	}
	return hmaState.active.Location
}

func (h HideMyAss) Status(ctx context.Context) provider.Status {
	hmaState.mu.RLock()
	active := hmaState.active
	hmaState.mu.RUnlock()
	if active == nil || active.VIP == "" || active.Tunnel == nil || active.VIP != active.Tunnel.address() {
		return provider.Status{Provider: name}
	}
	region := active.Country
	if active.Server.Geo.City != "" {
		region += " - " + active.Server.Geo.City
	}
	return provider.Status{Provider: name, Connected: true, Location: active.Location, Region: region, IP: probePublicIP(ctx, func(ctx context.Context, _, addr string) (net.Conn, error) { return dialTunnel(ctx, addr) })}
}

func (HideMyAss) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmdSilent(ctx, "openvpn", "--version")
	if err != nil {
		return "", errors.New("OpenVPN is unavailable")
	}
	return fmt.Sprintf("native HMA (%s)", strings.Split(strings.TrimSpace(out), "\n")[0]), nil
}
