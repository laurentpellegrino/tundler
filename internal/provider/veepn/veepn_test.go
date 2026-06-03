package veepn

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleOVPN = `client
pull
dev tun
proto udp
auth-user-pass
remote 146.70.19.146 23499
auth SHA512
cipher AES-256-CBC
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
xxx
-----END CERTIFICATE-----
</ca>
`

func TestLocationsAndActiveConfigRewrite(t *testing.T) {
	dir := t.TempDir()
	// Two locations, udp + tcp each — mimics the real archive naming.
	for _, fn := range []string{
		"ae.udp.veepn.com.ovpn", "ae.tcp.veepn.com.ovpn",
		"au-nsw.udp.veepn.com.ovpn", "au-nsw.tcp.veepn.com.ovpn",
	} {
		if err := os.WriteFile(filepath.Join(dir, fn), []byte(sampleOVPN), 0644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VEEPN_CONFIG_DIR", dir)
	t.Setenv("POD_NAME", "tundler-tunnel-veepn-0")
	t.Setenv("POD_0_VEEPN_USERNAME", "user0")
	t.Setenv("POD_0_VEEPN_PASSWORD", "pass0")
	serverCache = nil // reset package cache between runs

	v := VeePN{}

	// Locations() collapses udp+tcp into distinct location codes.
	locs := v.Locations(context.Background())
	if got := strings.Join(locs, ","); got != "ae,au-nsw" {
		t.Fatalf("Locations() = %q, want \"ae,au-nsw\"", got)
	}

	// Login validates per-pod creds + presence of configs.
	if err := v.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	// pickServer prefers udp.
	servers, _ := loadServers()
	s := pickServer(servers, "au-nsw")
	if s == nil || s.Proto != "udp" || s.Filename != "au-nsw.udp.veepn.com.ovpn" {
		t.Fatalf("pickServer(au-nsw) = %+v, want udp au-nsw", s)
	}

	// writeActiveConfig must rewrite the bare auth-user-pass to a file ref
	// and preserve everything else (remote, cipher, embedded ca).
	authPath, err := writeCredentials("user0", "pass0")
	if err != nil {
		t.Fatal(err)
	}
	dst, err := writeActiveConfig(s, authPath)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(dst)
	body := string(out)
	if !strings.Contains(body, "auth-user-pass "+authPath) {
		t.Errorf("active config missing rewritten auth-user-pass; got:\n%s", body)
	}
	if strings.Contains(body, "auth-user-pass\n") {
		t.Errorf("bare auth-user-pass not rewritten")
	}
	for _, want := range []string{"remote 146.70.19.146 23499", "cipher AES-256-CBC", "key-direction 1", "-----BEGIN CERTIFICATE-----"} {
		if !strings.Contains(body, want) {
			t.Errorf("active config dropped %q", want)
		}
	}
	// Credentials file content.
	cb, _ := os.ReadFile(authPath)
	if string(cb) != "user0\npass0\n" {
		t.Errorf("auth.txt = %q, want \"user0\\npass0\\n\"", string(cb))
	}
}
