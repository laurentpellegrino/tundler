package norton

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	ovpnrun "github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

var marseille = Server{IP: "138.199.14.130", Country: "FR", City: "Marseille", LocationKey: "FR-B8-MARSEILLE"}

func TestBuildConfig(t *testing.T) {
	cfg, err := buildOpenVPNConfig(&marseille, "/run/norton/openvpn-1/management.sock", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"remote 138.199.14.130 443 tcp\n",
		"dev tun-norton\ndev-type tun\n",
		"management \"/run/norton/openvpn-1/management.sock\" unix\n",
		"management-query-passwords\n", "auth-user-pass\n", "auth-nocache\n",
		"tun-mtu 1320\n", "mssfix 1280\n", "connect-retry-max 1\n",
		"cipher AES-256-GCM\n", "data-ciphers AES-256-GCM\n", "remote-cert-tls server\n",
		"route 0.0.0.0 0.0.0.0\n", "allow-recursive-routing\n",
		"<ca>\n-----BEGIN CERTIFICATE-----",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q", want)
		}
	}
	if strings.Contains(cfg, "auth-user-pass /") {
		t.Error("the password must come over the management socket, not from a file")
	}
	if _, err := buildOpenVPNConfig(&marseille, "/bad\"quote.sock", ""); err == nil {
		t.Error("a socket path that breaks quoting must be rejected")
	}
}

func TestBuildConfigUsesProvisionedCA(t *testing.T) {
	const minted = "-----BEGIN CERTIFICATE-----\nMINTEDCAPLACEHOLDER\n-----END CERTIFICATE-----"
	cfg, err := buildOpenVPNConfig(&marseille, "/run/norton/openvpn-1/management.sock", minted)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "MINTEDCAPLACEHOLDER") {
		t.Error("a provisioned CA must be used in place of the embedded one")
	}
	if strings.Contains(cfg, strings.TrimSpace(embeddedCACert)) {
		t.Error("the embedded CA must not appear when a provisioned CA is given")
	}
}

func TestMachineIdentityStableAndWellFormed(t *testing.T) {
	t.Setenv("NORTON_MACHINE_ID", "")
	a := machineIdentityFor("tundler-tunnel-norton-0")
	b := machineIdentityFor("tundler-tunnel-norton-0")
	if a != b {
		t.Fatalf("identity not stable for a seed: %+v vs %+v", a, b)
	}
	if c := machineIdentityFor("tundler-tunnel-norton-1"); c == a {
		t.Fatal("different seeds must yield different identities")
	}
	if len(a.endpointID) != 36 || strings.Count(a.endpointID, "-") != 4 {
		t.Errorf("endpoint id not UUID-shaped: %q", a.endpointID)
	}
	if len(a.fingerprint) != 16 {
		t.Errorf("fingerprint not 16 hex chars: %q", a.fingerprint)
	}
	t.Setenv("NORTON_MACHINE_ID", "pinned-seed")
	if machineIdentityFor("ignored") != machineIdentityFor("also-ignored") {
		t.Error("NORTON_MACHINE_ID must pin the identity regardless of seed")
	}
}

func TestExtractVPNPassage(t *testing.T) {
	body := []byte(`{"data":[[
		{"Job":"APPLYPRODUCTINSTANCE","Data":{"productInstance":"x"}},
		{"Job":"OXYGENBIND","Data":{"ConnectToken":"1"}},
		{"Job":"APPLYSERVICERESPONSE","Data":{"vpn_passage":{"http_code":200,"response":{"status":{"code":0},"data":{
			"token":{"access_token":"a","refresh_token":"b"},
			"credentials":{"device_udid":"U1.tenant.nlk401.deadbeef","device_password":"pw","openvpn_ca_certificate":"  -----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----  "}
		}}}}}
	]],"error":null,"success":true}`)
	cred, err := extractVPNPassage(body)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Username != "U1.tenant.nlk401.deadbeef" || cred.Password != "pw" {
		t.Fatalf("credential = %+v", cred)
	}
	if !strings.HasPrefix(cred.CA, "-----BEGIN") || strings.HasSuffix(cred.CA, " ") {
		t.Errorf("CA not trimmed: %q", cred.CA)
	}
	if _, err := extractVPNPassage([]byte(`{"data":[[{"Job":"X","Data":{"y":1}}]]}`)); err == nil {
		t.Error("a response without vpn_passage must error")
	}
}

func TestEmbeddedServersParse(t *testing.T) {
	servers, err := loadServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) == 0 {
		t.Fatal("embedded server snapshot is empty")
	}
	for _, s := range servers {
		if s.IP == "" {
			t.Errorf("server has no IP: %+v", s)
		}
	}
}

// withServer serves a one-server pool, a per-device credential and a stubbed
// openvpn start, so Connect never reads the embedded list or starts the
// openvpn installed on a desktop.
func withServer(t *testing.T, start func(context.Context, ovpnrun.Options, func(string) ([]byte, error)) (*ovpnrun.Tunnel, error)) {
	t.Helper()
	t.Setenv("TUNDLER_ACCOUNTS_DIR", t.TempDir())
	t.Setenv("TUNDLER_ACCOUNTS", "")
	t.Setenv("TUNDLER_ACCOUNT_USERNAME", "U1.tenant.nlk401.deadbeef")
	t.Setenv("TUNDLER_ACCOUNT_PASSWORD", "synthetic-device-secret")
	accounts.Reset()
	serverCacheMu.Lock()
	prevCache := serverCache
	serverCache = []Server{marseille}
	serverCacheMu.Unlock()
	prevStart := startTunnel
	startTunnel = start
	t.Cleanup(func() {
		serverCacheMu.Lock()
		serverCache = prevCache
		serverCacheMu.Unlock()
		startTunnel = prevStart
		activeMu.Lock()
		current = nil
		activeMu.Unlock()
		accounts.Reset()
	})
}

func TestConnectReportsAServerRefusingTheCredentials(t *testing.T) {
	var (
		opts ovpnrun.Options
		cfg  []byte
	)
	withServer(t, func(_ context.Context, o ovpnrun.Options, render func(string) ([]byte, error)) (*ovpnrun.Tunnel, error) {
		opts = o
		var err error
		if cfg, err = render("/run/norton/openvpn-1/management.sock"); err != nil {
			return nil, err
		}
		return nil, ovpnrun.ErrAuthFailed
	})
	st := Norton{}.Connect(context.Background(), "FR")
	if st.Connected || !st.AuthFailed || st.Location != "FR" {
		t.Fatalf("status = %+v, want AuthFailed at FR", st)
	}
	if opts.User != "U1.tenant.nlk401.deadbeef" || opts.Pass != "synthetic-device-secret" {
		t.Fatal("the credentials must be handed to the management exchange")
	}
	if strings.Contains(string(cfg), "synthetic-device-secret") {
		t.Fatal("the password must not be written into the config")
	}
}

func TestConnectReportsOtherFailuresAsPlainFailures(t *testing.T) {
	withServer(t, func(context.Context, ovpnrun.Options, func(string) ([]byte, error)) (*ovpnrun.Tunnel, error) {
		return nil, errors.New("norton OpenVPN connection timed out")
	})
	if st := (Norton{}).Connect(context.Background(), "FR"); st.Connected || st.AuthFailed {
		t.Fatalf("status = %+v, want a plain failure", st)
	}
}

func TestActiveLocationRoundTripAndDisconnect(t *testing.T) {
	withServer(t, nil)
	if got := (Norton{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
	owned := exec.Command("sleep", "30")
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := ovpnrun.NewForTest(owned)
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: marseille, location: "FR"}
	activeMu.Unlock()
	if got := (Norton{}).ActiveLocation(context.Background()); got != "FR" {
		t.Fatalf("ActiveLocation = %q, want FR", got)
	}
	if got := activeRegion(); got != "FR - Marseille" {
		t.Fatalf("activeRegion = %q, want FR - Marseille", got)
	}
	if err := (Norton{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (Norton{}).ActiveLocation(context.Background()) != "" || activeRegion() != "" {
		t.Fatal("Disconnect must clear the active connection")
	}
	select {
	case <-tunnel.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect left the owned process running")
	}
}

func TestCheckEnvelopeSurfacesServerError(t *testing.T) {
	errBody := []byte(`{"error":{"code":-500,"type":"","message":"","additionalinfo":{"header":"Server error","content":"We're working to resolve an issue that prevents us from completing your request. <br>Try again later."}},"success":false}`)
	err := checkEnvelope(errBody)
	if err == nil {
		t.Fatal("expected an error for the -500 envelope, got nil")
	}
	if !strings.Contains(err.Error(), "-500") || !strings.Contains(err.Error(), "Server error") || !strings.Contains(err.Error(), "Try again later.") {
		t.Fatalf("error should carry the code and server message: %v", err)
	}
	if strings.Contains(err.Error(), "<br>") {
		t.Fatalf("error should strip the <br> markup: %v", err)
	}

	for _, ok := range [][]byte{
		[]byte(`{"success":true,"data":{"KeyLicense":{"Psn":"TFTW84QH8BW2"}}}`),
		[]byte(`{"data":{"foo":"bar"}}`),
		[]byte(`<!DOCTYPE html>`),
	} {
		if err := checkEnvelope(ok); err != nil {
			t.Fatalf("unexpected error for %q: %v", ok, err)
		}
	}
}
