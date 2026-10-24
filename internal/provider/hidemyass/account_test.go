package hidemyass

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAccountHandshake(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.Header.Get("Vaar-Version") != "0" || r.Header.Get("Vaar-Header-App-IPM-Product") != "79" {
			t.Error("incorrect native account protocol")
		}
		w.Header().Set("Vaar-Status", "0")
		switch r.URL.Path {
		case "/v1/command/login/email":
			var body struct {
				Email    string   `json:"email"`
				Password string   `json:"password"`
				Tickets  []string `json:"requestedTicketTypes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			if body.Email != "test@example.invalid" || body.Password != "test-password" || strings.Join(body.Tickets, ",") != "DEVT,LICT" {
				t.Error("incorrect login fields or ticket casing")
			}
			if r.Header.Get("Vaar-Header-Digest") == "" {
				t.Error("missing native request signature")
			}
			_, _ = w.Write([]byte(`{"tickets":{"DEVT":"device-ticket","LICT":"license-ticket"}}`))
		case "/v1/query/get-all-user-licenses":
			if r.Header.Get("Vaar-Header-Auth-Token") != "device-ticket" {
				t.Error("license query must use DEVT, not LICT")
			}
			_, _ = w.Write([]byte(`[{"id":"test-subscription","walletKeys":["test-key"],"expires":4102444800000,"product":{"familyCodes":["HideMyAss"]}}]`))
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := newAccountClient("test-device")
	if err != nil {
		t.Fatal(err)
	}
	client.baseURL = server.URL
	session, err := client.login(context.Background(), "test@example.invalid", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	licenses, err := client.licenses(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectLicense(licenses, time.Now()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("made %d calls, want login and license discovery", calls)
	}
}

func TestAccountRejectsVendorErrorsWithoutLeakingResponse(t *testing.T) {
	for _, status := range []string{"", "1", "100", "token-must-not-appear"} {
		t.Run(status, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Vaar-Status", status)
				w.Header().Set("Vaar-Header-Status-Debug", "secret-debug-value")
				_, _ = w.Write([]byte(`{"tickets":{"DEVT":"secret-ticket"},"password":"secret-password"}`))
			}))
			defer server.Close()
			c, err := newAccountClient("test-device")
			if err != nil {
				t.Error(err)
				return
			}
			c.baseURL = server.URL
			_, err = c.login(context.Background(), "test@example.invalid", "test-password")
			if err == nil {
				t.Fatal("HTTP 200 with failed Vaar status must not authenticate")
			}
			for _, forbidden := range []string{"secret-debug-value", "secret-ticket", "secret-password", "token-must-not-appear"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatal("account error exposed response data")
				}
			}
		})
	}
}

func TestAccountRejectsRedirectsAndOversizedResponses(t *testing.T) {
	for _, mode := range []string{"redirect", "oversized", "missing-ticket"} {
		t.Run(mode, func(t *testing.T) {
			followed := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirected" {
					followed = true
				}
				switch mode {
				case "redirect":
					http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
				case "oversized":
					w.Header().Set("Vaar-Status", "0")
					_, _ = w.Write([]byte(strings.Repeat("x", maxAPIResponse+1)))
				default:
					w.Header().Set("Vaar-Status", "0")
					_, _ = w.Write([]byte(`{"tickets":{}}`))
				}
			}))
			defer server.Close()
			c, err := newAccountClient("test-device")
			if err != nil {
				t.Error(err)
				return
			}
			c.baseURL = server.URL
			if _, err := c.login(context.Background(), "test@example.invalid", "test-password"); err == nil {
				t.Fatal("unsafe or incomplete account response accepted")
			}
			if followed {
				t.Fatal("account credentials followed an HTTP redirect")
			}
		})
	}
}

func TestSelectLicenseIgnoresExpiredAndUnrelatedSubscriptions(t *testing.T) {
	now := time.Now()
	var licenses []accountLicense
	raw := `[
  {"id":"test-subscription","walletKeys":["unrelated"],"expires":4102444800000,"product":{"familyCodes":["Other"]}},
  {"id":"test-subscription","walletKeys":["expired"],"expires":1,"product":{"familyCodes":["HideMyAss"]}},
  {"id":"test-subscription","walletKeys":[],"expires":4102444800000,"product":{"familyCodes":["HideMyAss"]}},
  {"walletKeys":["missing-container"],"expires":4102444800000,"product":{"familyCodes":["HideMyAss"]}},
  {"id":"test-subscription","walletKeys":["active"],"expires":4102444800000,"product":{"familyCodes":["HideMyAss"]}}
 ]`
	if err := json.Unmarshal([]byte(raw), &licenses); err != nil {
		t.Fatal(err)
	}
	got, err := selectLicense(licenses, now)
	if err != nil || got.WalletKeys[0] != "active" {
		t.Fatalf("failed to select active HMA license: %v", err)
	}
	if _, err := selectLicense(licenses[:3], now); err == nil {
		t.Fatal("accepted an ineligible subscription")
	}
}
