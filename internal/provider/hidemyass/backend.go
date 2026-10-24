package hidemyass

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const vpnURL = "https://api.se-platform.com"
const vpnAPIKey = "8FB96D5F6B7EB10670E03E4BD9EC1070B516AF5DA038A2FC574156B9A243AB94"

var errSessionExpired = errors.New("HMA device session expired")

type backendClient struct {
	http    *http.Client
	baseURL string
}

type deviceSession struct {
	UDID         string `json:"device_udid"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type vpnCredentials struct {
	DeviceUDID     string `json:"device_udid"`
	DevicePassword string `json:"device_password"`
	OpenVPNCA      string `json:"openvpn_ca_certificate"`
}

type credentialsResponse struct {
	Credentials vpnCredentials `json:"credentials"`
}

type locationCountry struct {
	CC      string         `json:"country_code"`
	Key     string         `json:"location_key"`
	Country string         `json:"country"`
	State   string         `json:"state"`
	Cities  []locationCity `json:"cities"`
}
type locationCity struct {
	Key   string `json:"location_key"`
	City  string `json:"location_city"`
	State string `json:"state"`
}

type vpnServer struct {
	IP       string `json:"ip"`
	Protocol string `json:"protocol"`
	UDPPorts []int  `json:"udp_ports"`
	Geo      struct {
		CC          string `json:"country_code"`
		City        string `json:"city"`
		LocationKey string `json:"location_key"`
	} `json:"geo"`
}

func newBackendClient() *backendClient {
	return &backendClient{baseURL: vpnURL, http: &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Responses and vendor debug text must never reach logs: they can contain
// device passwords, certificates, license keys, and bearer tokens.
func (c *backendClient) call(ctx context.Context, method, path, token string, body any, out any) error {
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return errors.New("encode HMA VPN request")
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, payload)
	if err != nil {
		return errors.New("create HMA VPN request")
	}
	sdkVersion := "7.0.0"
	if strings.HasPrefix(path, "/aladdin/") {
		sdkVersion = "mac-1.0.0"
	}
	for k, v := range map[string]string{
		"Content-Type": "application/json", "Accept": "application/json",
		"SE-Client-Type": "hma201", "SE-Client-Name": "com.privax.osx.provpn",
		"SE-Client-Version": "26.8.0", "SE-Client-Locale": "en-US",
		"SE-Operating-System-Type": "macOS", "SE-Operating-System-Version": "15.0",
		"SE-Platform-ID": "mac-x86-64", "SE-SDK-Version": sdkVersion,
		"SE-Client-API-KEY": vpnAPIKey, "X-NLOK-Tenant-ID": "3bfdc5ab-a90f-4503-8349-34d0991d33a3",
	} {
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("HMA VPN service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errSessionExpired
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HMA VPN API HTTP status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse+1))
	if err != nil {
		return errors.New("read HMA VPN response")
	}
	if len(raw) > maxAPIResponse {
		return errors.New("HMA VPN response exceeds size limit")
	}
	// Aladdin returns an unwrapped device object; other APIs use status/data.
	if !strings.HasPrefix(path, "/aladdin/") {
		var envelope struct {
			Status *struct {
				Code int `json:"code"`
			} `json:"status"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &envelope) != nil || envelope.Status == nil || len(envelope.Data) == 0 {
			return errors.New("invalid HMA VPN response envelope")
		}
		if envelope.Status.Code != 0 {
			return fmt.Errorf("HMA VPN API status %d", envelope.Status.Code)
		}
		raw = envelope.Data
	}
	if json.Unmarshal(raw, out) != nil {
		return errors.New("invalid HMA VPN response")
	}
	return nil
}

func (c *backendClient) associate(ctx context.Context, license accountLicense, fingerprint string) (deviceSession, error) {
	if license.ID == "" || len(license.WalletKeys) == 0 {
		return deviceSession{}, errors.New("HMA subscription has no device container")
	}
	var session deviceSession
	err := c.call(ctx, http.MethodPost, "/aladdin/v1/authorization/associate-license", "", struct {
		Key         string `json:"wallet_key"`
		Container   string `json:"container_id"`
		Fingerprint string `json:"device_fingerprint"`
		Package     string `json:"client_package_name"`
	}{license.WalletKeys[0], license.ID, fingerprint, "com.hidemyass.osx"}, &session)
	if err != nil {
		return deviceSession{}, err
	}
	if session.UDID == "" || session.AccessToken == "" || session.RefreshToken == "" {
		return deviceSession{}, errors.New("HMA returned an incomplete device session")
	}
	return session, nil
}

func (c *backendClient) credentials(ctx context.Context, session deviceSession) (vpnCredentials, error) {
	var response credentialsResponse
	err := c.call(ctx, http.MethodPut, "/passage/v6/devices/"+url.PathEscape(session.UDID)+"/credentials", session.AccessToken, struct{}{}, &response)
	if err != nil {
		return vpnCredentials{}, err
	}
	creds := response.Credentials
	if creds.DeviceUDID != session.UDID || creds.DevicePassword == "" || creds.OpenVPNCA == "" {
		return vpnCredentials{}, errors.New("HMA returned incomplete OpenVPN credentials")
	}
	return creds, nil
}

func (c *backendClient) locations(ctx context.Context, session deviceSession) ([]locationCountry, error) {
	var response struct {
		Countries []locationCountry `json:"geos"`
	}
	if err := c.call(ctx, http.MethodGet, "/discovery/v12/geos", session.AccessToken, nil, &response); err != nil {
		return nil, err
	}
	if len(response.Countries) == 0 {
		return nil, errors.New("HMA returned an empty location catalog")
	}
	return response.Countries, nil
}

func (c *backendClient) servers(ctx context.Context, session deviceSession, key string) ([]vpnServer, error) {
	var response struct {
		Servers []vpnServer `json:"ips"`
	}
	query := url.Values{"protocol": {"OPENVPN"}, "location_key": {key}}
	if err := c.call(ctx, http.MethodGet, "/discovery/v9/discover?"+query.Encode(), session.AccessToken, nil, &response); err != nil {
		return nil, err
	}
	if len(response.Servers) == 0 {
		return nil, errors.New("HMA returned no OpenVPN servers")
	}
	return response.Servers, nil
}

// The token was obtained over verified HTTPS. Its expiry is used only to decide
// when to reauthenticate, never as an independent proof of authorization.
func (s deviceSession) valid(now time.Time) bool {
	parts := strings.Split(s.AccessToken, ".")
	if len(parts) != 3 || s.UDID == "" || s.RefreshToken == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Expires int64 `json:"exp"`
	}
	return json.Unmarshal(raw, &claims) == nil && claims.Expires > now.Add(time.Minute).Unix()
}
