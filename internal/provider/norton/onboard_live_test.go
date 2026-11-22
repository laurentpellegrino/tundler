package norton

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveOnboard exercises the real activation flow against the backend. It is
// skipped unless NORTON_LIVE_ONBOARD=1 and a NORTON_PRODUCT_KEY are set, because
// it performs a live account activation (no tunnel). It prints only masked
// shapes, never the credential itself.
func TestLiveOnboard(t *testing.T) {
	if os.Getenv("NORTON_LIVE_ONBOARD") != "1" {
		t.Skip("set NORTON_LIVE_ONBOARD=1 and NORTON_PRODUCT_KEY to run")
	}
	key := os.Getenv("NORTON_PRODUCT_KEY")
	if key == "" {
		t.Skip("NORTON_PRODUCT_KEY not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	mid := machineIdentityFor(defaultMachineSeed())
	t.Logf("machine identity: endpoint=%s fingerprint=%s", mid.endpointID, mid.fingerprint)

	cred, err := onboardWithProductKey(ctx, key, mid)
	if err != nil {
		t.Fatalf("onboard failed: %v", err)
	}
	if !strings.HasPrefix(cred.Username, "U1.") {
		t.Errorf("username does not look like a device udid (prefix)")
	}
	t.Logf("MINTED ok: username_prefix=%q username_len=%d password_len=%d ca_present=%t",
		cred.Username[:min(12, len(cred.Username))], len(cred.Username), len(cred.Password), cred.CA != "")
}
