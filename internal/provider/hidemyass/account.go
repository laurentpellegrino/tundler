package hidemyass

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Account authentication follows AccountMy in the official macOS client.
// HTTP 200 alone does not indicate success: Vaar-Status is authoritative.
const accountURL = "https://my-mac.avast.com"
const accountAppSecret = "FCjslKx88eSOgpXXQUsdg744e1THNtGT"

const maxAPIResponse = 4 << 20

type accountClient struct {
	http      *http.Client
	baseURL   string
	requestID string
	deviceID  string
}

type accountSession struct {
	Tickets map[string]string `json:"tickets"`
}

type accountLicense struct {
	ID         string   `json:"id"`
	WalletKeys []string `json:"walletKeys"`
	Expires    int64    `json:"expires"`
	Product    struct {
		FamilyCodes []string `json:"familyCodes"`
	} `json:"product"`
}

func newAccountClient(deviceID string) (*accountClient, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("generate HMA request identity: %w", err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	deviceHash := sha256.Sum256([]byte(deviceID))
	deviceHash[6] = (deviceHash[6] & 0x0f) | 0x50
	deviceHash[8] = (deviceHash[8] & 0x3f) | 0x80
	return &accountClient{
		http:      &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
		baseURL:   accountURL,
		requestID: fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]),
		deviceID:  fmt.Sprintf("%X-%X-%X-%X-%X", deviceHash[:4], deviceHash[4:6], deviceHash[6:8], deviceHash[8:10], deviceHash[10:16]),
	}, nil
}

// call never returns response bodies or transport errors: both can contain
// account information, tickets, or request URLs with credentials.
func (c *accountClient) call(ctx context.Context, path, token, digest string, body any, result any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode HMA account request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("create HMA account request")
	}
	for k, v := range map[string]string{
		"Content-Type":                    "application/json",
		"Vaar-Version":                    "0",
		"Vaar-Header-App-Product-Brand":   "PRIVAX",
		"Vaar-Header-App-Build-Version":   "5.4.22",
		"Vaar-Header-App-Id":              c.requestID,
		"Vaar-Header-App-IPM-Product":     "79",
		"Vaar-Header-Device-Id":           c.deviceID,
		"Vaar-Header-Device-Platform":     "OSX",
		"Vaar-Header-App-Package-Name":    "com.privax.osx.provpn",
		"Vaar-Header-App-Product-Mode":    "PAID",
		"Vaar-Header-App-Product-Edition": "vpn",
	} {
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Vaar-Header-Auth-Token", token)
	}
	if digest != "" {
		req.Header.Set("Vaar-Header-Digest", digest)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("HMA account service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HMA account HTTP status %d", resp.StatusCode)
	}
	status := resp.Header.Get("Vaar-Status")
	if status != "0" {
		// Do not include the vendor's debug header: it is not a safe log source.
		return fmt.Errorf("HMA account authentication/request rejected (Vaar-Status %s)", safeStatus(status))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse+1))
	if err != nil {
		return fmt.Errorf("read HMA account response")
	}
	if len(raw) > maxAPIResponse {
		return fmt.Errorf("HMA account response exceeds size limit")
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return fmt.Errorf("invalid HMA account response")
	}
	return nil
}

func safeStatus(s string) string {
	if s == "" {
		return "missing"
	}
	if len(s) > 6 {
		return "invalid"
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return "invalid"
		}
	}
	return s
}

func (c *accountClient) login(ctx context.Context, username, password string) (accountSession, error) {
	digest := sha256.Sum256([]byte(accountAppSecret + c.requestID + username + ":" + password))
	var session accountSession
	err := c.call(ctx, "/v1/command/login/email", "", base64.StdEncoding.EncodeToString(digest[:]), struct {
		Email       string   `json:"email"`
		Password    string   `json:"password"`
		TicketTypes []string `json:"requestedTicketTypes"`
	}{username, password, []string{"DEVT", "LICT"}}, &session)
	if err != nil {
		return accountSession{}, err
	}
	if session.Tickets["DEVT"] == "" {
		return accountSession{}, fmt.Errorf("HMA login returned no device ticket")
	}
	return session, nil
}

func (c *accountClient) licenses(ctx context.Context, session accountSession) ([]accountLicense, error) {
	var licenses []accountLicense
	if err := c.call(ctx, "/v1/query/get-all-user-licenses", session.Tickets["DEVT"], "", struct{}{}, &licenses); err != nil {
		return nil, err
	}
	return licenses, nil
}

func selectLicense(licenses []accountLicense, now time.Time) (accountLicense, error) {
	for _, license := range licenses {
		if license.ID == "" || license.Expires <= now.UnixMilli() || len(license.WalletKeys) == 0 || license.WalletKeys[0] == "" {
			continue
		}
		for _, family := range license.Product.FamilyCodes {
			if family == "HideMyAss" {
				return license, nil
			}
		}
	}
	return accountLicense{}, fmt.Errorf("no active HMA subscription with a license key")
}
