package hidemyass

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixtureTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t fixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.URL.Scheme, copy.URL.Host = t.target.Scheme, t.target.Host
	return t.base.RoundTrip(copy)
}

func TestLoginReauthenticatesRejectedCachedSessionWithoutNewDeviceCredentials(t *testing.T) {
	resetHMA(t)
	t.Cleanup(func() { resetHMA(t) })
	t.Setenv("TUNDLER_ACCOUNTS_DIR", t.TempDir())
	t.Setenv("TUNDLER_ACCOUNTS", "")
	t.Setenv("TUNDLER_ACCOUNT_USERNAME", "synthetic@example.invalid")
	t.Setenv("TUNDLER_ACCOUNT_PASSWORD", "synthetic-password")
	t.Setenv("HIDEMYASS_DEVICE_ID", "synthetic-stable-pod")
	t.Setenv("HIDEMYASS_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":4102444800}`))
	stale, fresh := "stale."+claims+".signature", "fresh."+claims+".signature"
	saved := savedDevice{AccountHash: accountHash("synthetic@example.invalid", "synthetic-password"), Fingerprint: "synthetic-stable-pod", Session: deviceSession{UDID: "device", AccessToken: stale, RefreshToken: "refresh"}, Credentials: vpnCredentials{DeviceUDID: "device", DevicePassword: "cached-password", OpenVPNCA: "cached-ca"}}
	if err := saveDevice(stateDir(), saved); err != nil {
		t.Fatal(err)
	}
	associated, queried := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vaar-Status", "0")
		switch r.URL.Path {
		case "/discovery/v12/geos":
			queried++
			if r.Header.Get("Authorization") == "Bearer "+stale {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"status":{"code":0},"data":{"geos":[{"country_code":"GB","state":"active","location_key":"gb"}]}}`))
		case "/v1/command/login/email":
			_, _ = w.Write([]byte(`{"tickets":{"DEVT":"native-ticket"}}`))
		case "/v1/query/get-all-user-licenses":
			_, _ = w.Write([]byte(`[{"id":"subscription","walletKeys":["key"],"expires":4102444800000,"product":{"familyCodes":["HideMyAss"]}}]`))
		case "/aladdin/v1/authorization/associate-license":
			associated++
			var body struct {
				Fingerprint string `json:"device_fingerprint"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Fingerprint != saved.Fingerprint {
				t.Error("reauthentication changed device fingerprint")
			}
			_ = json.NewEncoder(w).Encode(deviceSession{UDID: "device", AccessToken: fresh, RefreshToken: "new-refresh"})
		default:
			t.Error("reauthentication unnecessarily provisioned credentials or used an unexpected endpoint")
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	previous := http.DefaultTransport
	http.DefaultTransport = fixtureTransport{target: target, base: previous}
	t.Cleanup(func() { http.DefaultTransport = previous })
	if err := (HideMyAss{}).Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	if associated != 1 || queried != 2 || hmaState.device.Session.AccessToken != fresh || hmaState.device.Credentials.DevicePassword != saved.Credentials.DevicePassword {
		t.Fatal("rejected cache did not heal with stable device credential reuse")
	}
}

func TestNativeDeviceAndDiscoveryFlow(t *testing.T) {
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("SE-Platform-ID") != "mac-x86-64" || r.Header.Get("SE-Client-Type") != "hma201" {
			t.Error("incorrect native platform headers")
		}
		switch r.URL.Path {
		case "/aladdin/v1/authorization/associate-license":
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid license request")
				return
			}
			if r.Method != "POST" || r.Header.Get("SE-SDK-Version") != "mac-1.0.0" || body["container_id"] != "container" || body["device_fingerprint"] != "stable-device" {
				t.Error("incorrect device association")
			}
			_, _ = w.Write([]byte(`{"device_udid":"device","access_token":"access","refresh_token":"refresh"}`))
		case "/passage/v6/devices/device/credentials":
			if r.Method != "PUT" || r.Header.Get("Authorization") != "Bearer access" || r.Header.Get("SE-SDK-Version") != "7.0.0" {
				t.Error("incorrect credential provisioning")
			}
			_, _ = w.Write([]byte(`{"status":{"code":0},"data":{"credentials":{"device_udid":"device","device_password":"password","openvpn_ca_certificate":"ca"}}}`))
		case "/discovery/v12/geos":
			if r.Method != "GET" {
				t.Error("location catalog is not a GET")
			}
			_, _ = w.Write([]byte(`{"status":{"code":0},"data":{"geos":[{"country_code":"GB","country":"UK","state":"active","location_key":"gb"}]}}`))
		case "/discovery/v9/discover":
			if r.Method != "GET" || r.URL.Query().Get("protocol") != "OPENVPN" || r.URL.Query().Get("location_key") != "gb" {
				t.Error("incorrect server discovery version or parameters")
			}
			_, _ = w.Write([]byte(`{"status":{"code":0},"data":{"ips":[{"ip":"192.0.2.1","protocol":"OPENVPN","handshake_data":{"remote_identifier":"vpn.example"}}]}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	c := newBackendClient()
	c.baseURL = server.URL
	license := accountLicense{ID: "container", WalletKeys: []string{"license"}}
	session, err := c.associate(context.Background(), license, "stable-device")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.credentials(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if _, err := c.locations(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if _, err := c.servers(context.Background(), session, "gb"); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 4 {
		t.Fatal("unexpected request count")
	}
}

func TestBackendRejectsUntrustedErrorText(t *testing.T) {
	for _, body := range []string{`{"status":{"code":2004,"message":"private-token"},"data":{}}`, `{"data":{"private":"private-token"}}`, `malformed-private-token`} {
		t.Run(body[:8], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			c := newBackendClient()
			c.baseURL = server.URL
			_, err := c.locations(context.Background(), deviceSession{AccessToken: "secret"})
			if err == nil || strings.Contains(err.Error(), "private-token") {
				t.Fatal("accepted or exposed an unsafe backend response")
			}
		})
	}
}

func TestDeviceCachePermissionsAndIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":4102444800}`))
	saved := savedDevice{AccountHash: "account-a", Fingerprint: "pod-a", Session: deviceSession{UDID: "device", AccessToken: "header." + claims + ".signature", RefreshToken: "refresh"}, Credentials: vpnCredentials{DeviceUDID: "device", DevicePassword: "password", OpenVPNCA: "ca"}}
	if err := saveDevice(dir, saved); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadDevice(dir, "account-a", "pod-a"); !ok {
		t.Fatal("valid device cache was not reused")
	}
	if !saved.Session.valid(time.Now()) {
		t.Fatal("valid device token marked expired")
	}
	if _, ok := loadDevice(dir, "account-b", "pod-a"); ok {
		t.Fatal("reused another account's device")
	}
	if _, ok := loadDevice(dir, "account-a", "pod-b"); ok {
		t.Fatal("reused another pod's device")
	}
	path := filepath.Join(dir, "device.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("device cache is not private")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadDevice(dir, "account-a", "pod-a"); ok {
		t.Fatal("accepted an exposed device cache")
	}
}

func TestFingerprintIsStableAndDistinct(t *testing.T) {
	t.Setenv("HIDEMYASS_DEVICE_ID", "")
	t.Setenv("POD_NAME", "tundler-hidemyass-0")
	a := deviceFingerprint("account-a")
	if a != deviceFingerprint("account-a") {
		t.Fatal("unstable device fingerprint")
	}
	t.Setenv("POD_NAME", "tundler-hidemyass-1")
	if a == deviceFingerprint("account-a") {
		t.Fatal("pods share a device fingerprint")
	}
	if deviceFingerprint("account-a") == deviceFingerprint("account-b") {
		t.Fatal("accounts share a device fingerprint")
	}
	t.Setenv("HIDEMYASS_DEVICE_ID", "development-device")
	if deviceFingerprint("account-a") != "development-device" {
		t.Fatal("explicit device identity ignored")
	}
}
