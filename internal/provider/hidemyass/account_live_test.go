package hidemyass

import (
	"context"
	"os"
	"testing"
	"time"
)

// This checks account authentication and subscription discovery only. It does
// not exchange license keys, register a VPN device, or establish a tunnel.
func TestLiveAccount(t *testing.T) {
	if os.Getenv("HIDEMYASS_LIVE_TEST") != "1" {
		t.Skip("set HIDEMYASS_LIVE_TEST=1 with account credentials in the environment")
	}
	username := os.Getenv("TUNDLER_ACCOUNT_USERNAME")
	password := os.Getenv("TUNDLER_ACCOUNT_PASSWORD")
	if username == "" || password == "" {
		t.Fatal("set TUNDLER_ACCOUNT_USERNAME and TUNDLER_ACCOUNT_PASSWORD")
	}
	client, err := newAccountClient("tundler-hidemyass-account-check")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	session, err := client.login(ctx, username, password)
	if err != nil {
		t.Fatal(err)
	}
	licenses, err := client.licenses(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectLicense(licenses, time.Now()); err != nil {
		t.Fatal(err)
	}
}
