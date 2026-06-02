// TunnelBear / PolarBear API client.
//
// TunnelBear's "VPN" used by the browser extension is not a kernel
// tunnel but an authenticated HTTPS CONNECT proxy. The control plane
// is reverse-engineered from the official Chrome extension
// (omdakjcmkglenbhjadbccaookpfjihpa, v4.2.0) and the open-source
// tn3w/TunnelBear-IPs auth flow:
//
//	1. GET  prod-api-core.tunnelbear.com/core/web/xzrf        → CSRF token + cookies
//	2. POST prod-api-dashboard.tunnelbear.com/.../v2/token    → account access_token
//	   (body: username/password/grant_type=password/device)
//	3. POST api.polargrizzly.com/auth                         → PolarBear bearer (pb token)
//	   (body: partner=tunnelbear, token=access_token; bearer in Authorization resp header)
//	4. GET  api.polargrizzly.com/user                         → { vpn_token, is_data_unlimited, ... }
//	5. GET  api.polargrizzly.com/vpns/countries/<cc>          → { vpns:[{host,url,port,...}], ... }
//
// The proxy is then reached at <server.url>:8080 over TLS, authorizing
// every CONNECT with Proxy-Authorization: Basic base64(vpn_token:vpn_token).
package tunnelbear

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"
)

const (
	urlXZRF      = "https://prod-api-core.tunnelbear.com/core/web/xzrf"
	urlDashToken = "https://prod-api-dashboard.tunnelbear.com/dashboard/web/v2/token"
	urlPBAuth    = "https://api.polargrizzly.com/auth"
	urlPBUser    = "https://api.polargrizzly.com/user"
	urlPBVpns    = "https://api.polargrizzly.com/vpns/countries/"

	// Browser-ish UA + the extension/web app identity headers. The
	// dashboard token endpoint rejects requests without a matching
	// app-id, and the CSRF cookie is bound to this Origin.
	userAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0.1) Gecko/20100101 Firefox/138.0.1"
	appID      = "com.tunnelbear.web"
	appVersion = "1.0.0"
	webOrigin  = "https://www.tunnelbear.com"

	// proxyPort is the HTTPS CONNECT proxy port every lazerpenguin.com
	// edge listens on (from the extension's makeProxyRequestListener).
	proxyPort = "8080"
)

// vpnServer is one entry from /vpns/countries/<cc>. host is the raw IP
// (also the exit IP), url is the cert-matching hostname we TLS-dial.
type vpnServer struct {
	Host string `json:"host"`
	URL  string `json:"url"`
	Port int    `json:"port"`
}

type vpnsResponse struct {
	RegionName string      `json:"region_name"`
	CountryISO string      `json:"country_iso"`
	Vpns       []vpnServer `json:"vpns"`
}

type userInfo struct {
	VpnToken        string `json:"vpn_token"`
	IsDataUnlimited bool   `json:"is_data_unlimited"`
	Tier            int    `json:"tier"`
	AccountStatus   string `json:"account_status"`
}

// apiClient performs the auth handshake and authenticated GETs. One
// instance carries the CSRF cookie jar for a single login.
type apiClient struct {
	hc       *http.Client
	csrf     string
	deviceID string
}

func newAPIClient() *apiClient {
	jar, _ := cookiejar.New(nil)
	return &apiClient{
		hc:       &http.Client{Jar: jar, Timeout: 20 * time.Second},
		deviceID: deviceID(),
	}
}

// deviceID is stable per pod (so we don't register a new "device" on
// every login and churn TunnelBear's device list). Falls back to a
// random id when POD_NAME is unset (local runs).
func deviceID() string {
	if pod := os.Getenv("POD_NAME"); pod != "" {
		return "tundler-" + pod
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "tundler-" + hex.EncodeToString(b)
}

func (c *apiClient) getCSRF(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlXZRF, nil)
	c.webHeaders(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("csrf request: %w", err)
	}
	defer drain(resp)
	tok := resp.Header.Get("tb-csrf-token")
	if tok == "" {
		return fmt.Errorf("csrf: no tb-csrf-token header (status %d)", resp.StatusCode)
	}
	c.csrf = tok
	return nil
}

// dashboardToken logs the account in and returns the access_token.
func (c *apiClient) dashboardToken(ctx context.Context, username, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"username":   username,
		"password":   password,
		"grant_type": "password",
		"device":     c.deviceID,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, urlDashToken, bytes.NewReader(body))
	c.webHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("TB-CSRF-Token", c.csrf)
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("dashboard token request: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dashboard token: status %d (check TUNNELBEAR_USERNAME/PASSWORD)", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("dashboard token decode: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("dashboard token: empty access_token")
	}
	return out.AccessToken, nil
}

// exchangePB swaps the account access_token for a PolarBear bearer.
func (c *apiClient) exchangePB(ctx context.Context, accessToken string) (string, error) {
	body, _ := json.Marshal(map[string]string{"partner": "tunnelbear", "token": accessToken})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, urlPBAuth, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("polarbear auth request: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("polarbear auth: status %d", resp.StatusCode)
	}
	pb := strings.TrimPrefix(resp.Header.Get("authorization"), "Bearer ")
	if pb == "" {
		return "", fmt.Errorf("polarbear auth: no authorization header")
	}
	return pb, nil
}

func (c *apiClient) getUser(ctx context.Context, pbToken string) (userInfo, error) {
	var ui userInfo
	if err := c.pbGet(ctx, urlPBUser, pbToken, &ui); err != nil {
		return ui, fmt.Errorf("user info: %w", err)
	}
	return ui, nil
}

func (c *apiClient) getServers(ctx context.Context, pbToken, country string) (vpnsResponse, error) {
	var vr vpnsResponse
	if err := c.pbGet(ctx, urlPBVpns+country, pbToken, &vr); err != nil {
		return vr, fmt.Errorf("servers for %q: %w", country, err)
	}
	return vr, nil
}

// pbGet issues an authenticated PolarBear GET and decodes JSON.
func (c *apiClient) pbGet(ctx context.Context, url, pbToken string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("authorization", "Bearer "+pbToken)
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *apiClient) webHeaders(req *http.Request) {
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("tunnelbear-app-id", appID)
	req.Header.Set("tunnelbear-app-version", appVersion)
	req.Header.Set("Origin", webOrigin)
	req.Header.Set("Referer", webOrigin+"/")
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
}
