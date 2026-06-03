package windscribe

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildConfig(t *testing.T) {
	cfg := buildOpenVPNConfig(node{Hostname: "ber-449.whiskergalaxy.com"}, "/etc/windscribe/openvpn/auth.txt")
	for _, want := range []string{
		"remote ber-449.whiskergalaxy.com 443",
		"auth-user-pass /etc/windscribe/openvpn/auth.txt",
		"cipher AES-256-GCM", "auth SHA512", "key-direction 1",
		"-----BEGIN CERTIFICATE-----", "-----BEGIN OpenVPN Static key V1-----",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q", want)
		}
	}
}

func TestEmbeddedFallbackParses(t *testing.T) {
	var sl serverList
	if err := json.Unmarshal(embeddedServers, &sl); err != nil {
		t.Fatalf("embedded servers.json invalid: %v", err)
	}
	withNodes := 0
	for _, l := range sl.Data {
		if len(l.Nodes) > 0 {
			withNodes++
		}
	}
	if withNodes < 20 {
		t.Errorf("embedded fallback has only %d locations with nodes (<20)", withNodes)
	}
	t.Logf("embedded fallback: %d locations, %d with nodes", len(sl.Data), withNodes)
}
