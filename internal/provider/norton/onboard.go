package norton

// Self-provisioning: mint a per-device OpenVPN credential from the product key
// alone, with no interactive sign-in. The backend's activation service
// (cloudconnect2.norton.com) hands the credential back inline when the key is
// activated on a device, so a pod that holds only the product key can provision
// itself. The flow mirrors the app's own WebView activation, reduced to its
// four HTTPS calls:
//
//	1. GET  /cloudconnect/home/           -> session cookies + an antiforgery token
//	2. POST /ccapi/mine/save              -> register this device (a generated,
//	                                         pod-stable machine identity) and ask
//	                                         for the vpn_passage service
//	3. POST /ccapi/license/verifykey      -> the key's product serial (PSN)
//	   POST /ccapi/license/registernewkey -> bind the key to this device
//	4. GET  /ccapi/license/activate/<PSN> -> a jobs array whose vpn_passage block
//	                                         carries device_udid/device_password
//	                                         (the OpenVPN user/pass) and the CA
//
// No account login and no OAuth are involved: the key itself resolves to the
// backend account. The machine identity is derived from the pod hostname so a
// restart reclaims the same seat instead of consuming a new one.

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	urlpkg "net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	cloudConnectBase = "https://cloudconnect2.norton.com"
	// clientType is the backend's device-class tag; it is the literal that
	// appears in a minted OpenVPN username (U1.<tenant>.nlk401.<hex>) and the
	// value the activation service keys the vpn_passage credential on.
	clientType = "nlk401"
	// clientVersion is the app version the activation service expects in the
	// vpn_passage request; it gates the credential shape, not the tunnel.
	clientVersion = "26.20.0"
	// fullVersion is the app's full build string, used in the CCT product tag.
	fullVersion = "26.20.0.261030325"
	// tenantGUID is the Norton VPN tenant the activation runs under; it is baked
	// into the app and prefixes every minted OpenVPN username.
	tenantGUID = "de527324-05e3-46eb-a2a7-43ab29c1aff7"
	// appPackage is the app whose WebView drives the activation page. The
	// backend expects it in X-Requested-With (Android sets this header to the
	// hosting app's package); a browser value makes mine/save fail server-side.
	appPackage = "com.symantec.securewifi"
	// onboardUA is the WebView user agent (note the "wv" token); the cloudconnect
	// endpoint expects the in-app WebView, not a plain browser.
	onboardUA = "Mozilla/5.0 (Linux; Android 12; sdk_gphone64_x86_64 Build/SE1B.240122.005; wv) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36"
	onboardTimeout = 60 * time.Second
)

// deviceCredential is what a product-key activation mints: the per-device
// OpenVPN username/password and the backend's OpenVPN CA chain.
type deviceCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	CA       string `json:"ca"`
}

func (c deviceCredential) valid() bool {
	return c.Username != "" && c.Password != ""
}

// machineIdentity is the device identity the activation service binds a seat to.
// It must be stable for a given pod so restarts reclaim the same seat rather than
// burn a new one; it is derived from a pod-stable seed (POD_NAME, else hostname,
// else NORTON_MACHINE_ID to pin it) so every ordinal of a StatefulSet keeps its
// own seat. On a multi-seat plan this is the whole seat model: ordinal N owns one
// seat and re-activates it idempotently, so keeping replicas <= the plan's seat
// limit means seats never leak and no account-gated seat transfer is ever needed.
type machineIdentity struct {
	endpointID  string // canonical UUID form
	fingerprint string // first eight bytes, uppercase hex
}

func machineIdentityFor(seed string) machineIdentity {
	// NORTON_MACHINE_ID may pin the identity: a raw UUID is used verbatim, any
	// other string is a seed. This lets an operator reproduce a known device.
	if v := strings.TrimSpace(os.Getenv("NORTON_MACHINE_ID")); v != "" {
		if b, ok := parseUUID(v); ok {
			return identityFromBytes(b)
		}
		seed = v
	}
	sum := sha1.Sum([]byte("tundler-norton-machine:" + seed))
	b := append([]byte(nil), sum[:16]...)
	// Stamp a UUID (the app uses version 3 here); the fingerprint is then
	// derived from these exact bytes so the two agree.
	b[6] = (b[6] & 0x0f) | 0x30
	b[8] = (b[8] & 0x3f) | 0x80
	return identityFromBytes(b)
}

// identityFromBytes derives the endpoint id and its paired fingerprint. The
// backend expects Fingerprint to equal the endpoint's first eight bytes with the
// UUID version nibble cleared (byte six's high nibble), which is how the app's
// own pair relates (endpoint cc555712-ee01-3fb7-... -> fingerprint CC555712EE010FB7).
func identityFromBytes(b []byte) machineIdentity {
	fp := append([]byte(nil), b[:8]...)
	fp[6] &= 0x0f
	return machineIdentity{
		endpointID:  formatUUID(b),
		fingerprint: strings.ToUpper(hex.EncodeToString(fp)),
	}
}

// parseUUID accepts a canonical 8-4-4-4-12 UUID and returns its sixteen bytes.
func parseUUID(s string) ([]byte, bool) {
	h := strings.ReplaceAll(s, "-", "")
	if len(h) != 32 {
		return nil, false
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, false
	}
	return b, true
}

// newUUID returns a random RFC-4122 version-4 UUID string.
func newUUID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		// crypto/rand failing is fatal elsewhere; fall back to a time seed so
		// onboarding still yields a well-formed, unique-enough identifier.
		for i := range b {
			b[i] = byte(rand.Intn(256))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return formatUUID(b[:])
}

// formatUUID renders sixteen bytes in canonical 8-4-4-4-12 form.
func formatUUID(b []byte) string {
	s := hex.EncodeToString(b[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}

// defaultMachineSeed is the pod-stable seed for the machine identity. It prefers
// POD_NAME (the StatefulSet downward-API name, e.g. tundler-tunnel-norton-0) so a
// pod keeps the same seat across restarts and each ordinal binds its own seat;
// os.Hostname() is the same value inside a pod and covers local runs, and the
// static string is a last resort. Same convention as the tunnelbear/hidemyass
// per-pod device identities.
func defaultMachineSeed() string {
	if p := strings.TrimSpace(os.Getenv("POD_NAME")); p != "" {
		return p
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "tundler-norton"
}

// onboardClient drives the activation HTTPS flow with a cookie jar.
type onboardClient struct {
	http      *http.Client
	base      string
	traceID   string
	xsrfToken string
}

func newOnboardClient() (*onboardClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &onboardClient{
		http:    &http.Client{Jar: jar, Timeout: onboardTimeout},
		base:    cloudConnectBase,
		traceID: newUUID(),
	}, nil
}

// onboardWithProductKey runs the full activation and returns the device
// credential. It performs real activation calls against the backend, so callers
// should cache the result and not call it on every connect.
func onboardWithProductKey(ctx context.Context, productKey string, mid machineIdentity) (deviceCredential, error) {
	productKey = strings.TrimSpace(productKey)
	if productKey == "" {
		return deviceCredential{}, fmt.Errorf("norton onboard: empty product key")
	}
	c, err := newOnboardClient()
	if err != nil {
		return deviceCredential{}, err
	}
	if err := c.openSession(ctx); err != nil {
		return deviceCredential{}, err
	}
	if err := c.registerMachine(ctx, mid); err != nil {
		return deviceCredential{}, err
	}
	psn, err := c.verifyKey(ctx, productKey)
	if err != nil {
		return deviceCredential{}, err
	}
	if err := c.registerNewKey(ctx, productKey); err != nil {
		return deviceCredential{}, err
	}
	cred, err := c.activate(ctx, psn)
	if err != nil {
		return deviceCredential{}, err
	}
	if !cred.valid() {
		return deviceCredential{}, fmt.Errorf("norton onboard: activation returned no device credential")
	}
	shared.Debugf("norton: self-provisioned a device credential from the product key (PSN %s)", psn)
	return cred, nil
}

var rvtRe = regexp.MustCompile(`RequestVerificationToken"[^>]*\bvalue="([^"]+)"`)

// seedContextCookie pre-sets the CCT cookie the native app installs before
// opening the WebView. It carries the product tag (pdt), the tenant and the
// launch context; without it the activation service has no product context and
// fails every /ccapi call with a generic server error. The value is the app's
// exact URL-encoded form with this session's trace id substituted in.
func (c *onboardClient) seedContextCookie() error {
	u, err := urlpkg.Parse(c.base)
	if err != nil {
		return err
	}
	val := "%26pdt%3DNSV%2F" + fullVersion + "%2FAndroid%2F12%26debug%3Dfalse" +
		"%26launchurl%3D%25252fcloudconnect%25252fhome%25252f%25253fgentraceid%25253d" + c.traceID +
		"%26xteleid%3D" + c.traceID +
		"%26xtenantname%3DNortonGen" +
		"%26xtenantid%3D" + tenantGUID +
		"%26gentheme%3Dlight%26showgenstacklayout%3Dtrue%26ismultitenantcapable%3Dtrue%26showcurvededges%3Dfalse"
	c.http.Jar.SetCookies(u, []*http.Cookie{{Name: "CCT", Value: val, Path: "/"}})
	return nil
}

// openSession loads the activation page to seed the cookie jar and read the
// antiforgery token that the /ccapi calls must echo.
func (c *onboardClient) openSession(ctx context.Context) error {
	if err := c.seedContextCookie(); err != nil {
		return err
	}
	u := fmt.Sprintf("%s/cloudconnect/home/?gentraceid=%s", c.base, c.traceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", onboardUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("X-Requested-With", appPackage)
	// The authoritative product context (pdt/tenant) the server writes into the
	// CCT.Session cookie is read from these headers on the home GET, not from the
	// pre-seeded CCT cookie (which the server ignores for these fields). Without
	// them every /ccapi call fails -500 for lack of product context.
	req.Header.Set("x-nlok-tenant-id", tenantGUID)
	req.Header.Set("x-symc-user-agent", "NSV/"+fullVersion+"/Android/12")
	req.Header.Set("x-nlok-trace-id", c.traceID)
	req.Header.Set("Sec-Ch-Ua", secChUA)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?1")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Android"`)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	body, _, err := c.do(req)
	if err != nil {
		return fmt.Errorf("norton onboard: open session: %w", err)
	}
	m := rvtRe.FindSubmatch(body)
	if m == nil {
		return fmt.Errorf("norton onboard: no antiforgery token on the activation page")
	}
	c.xsrfToken = string(m[1])
	return nil
}

// registerMachine posts the device identity and asks the activation service to
// include the vpn_passage credential in the activation.
func (c *onboardClient) registerMachine(ctx context.Context, mid machineIdentity) error {
	customData, _ := json.Marshal(map[string]any{
		"authonlyprovidepi": false,
		"certificateserial": randomSerial(),
	})
	b2bs, _ := json.Marshal([]map[string]any{{
		"service": "vpn_passage",
		"payload": map[string]string{"clientVersion": clientVersion, "clientType": clientType},
	}})
	payload := map[string]any{
		"Action":                    "enterkey",
		"OSLocale":                  "US",
		"OSLanguage":                "en",
		"Fingerprint":               mid.fingerprint,
		"EndPointId":                mid.endpointID,
		"MachineName":               machineName(),
		"ManufacturerModel":         "Pixel 8",
		"ManufacturerName":          "Google",
		"Country":                   "us",
		"ApplicationMajorVersionId": "2846",
		"LayoutProductLanguage":     "en",
		"LayoutXlokSKU":             3690,
		"LayoutMediaSKU":            "21366757",
		"SchemaCategory":            "SBU_MOBILE",
		"SchemaVersion":             "2.0.0.0",
		"RequesterIds":              "https://accesstoken.securevpn.norton.com",
		"ClientCustomData":          string(customData),
		"B2Bs":                      string(b2bs),
		"ClientData":                newUUID(),
	}
	if err := c.postJSON(ctx, "/ccapi/mine/save", payload, nil); err != nil {
		return fmt.Errorf("norton onboard: register machine: %w", err)
	}
	return nil
}

func (c *onboardClient) verifyKey(ctx context.Context, key string) (string, error) {
	var out struct {
		Data struct {
			KeyLicense struct {
				Psn string `json:"Psn"`
			} `json:"KeyLicense"`
		} `json:"data"`
	}
	if err := c.postJSON(ctx, "/ccapi/license/verifykey", map[string]string{"Key": key, "Token": ""}, &out); err != nil {
		return "", fmt.Errorf("norton onboard: verify key: %w", err)
	}
	if out.Data.KeyLicense.Psn == "" {
		return "", fmt.Errorf("norton onboard: verify key returned no product serial (key not recognised?)")
	}
	return out.Data.KeyLicense.Psn, nil
}

func (c *onboardClient) registerNewKey(ctx context.Context, key string) error {
	if err := c.postJSON(ctx, "/ccapi/license/registernewkey", map[string]string{"Key": key}, nil); err != nil {
		return fmt.Errorf("norton onboard: register key: %w", err)
	}
	return nil
}

// activate pulls the jobs array and extracts the vpn_passage credential.
func (c *onboardClient) activate(ctx context.Context, psn string) (deviceCredential, error) {
	u := fmt.Sprintf("%s/ccapi/license/activate/%s", c.base, psn)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return deviceCredential{}, err
	}
	c.apiHeaders(req, false)
	body, status, err := c.do(req)
	if err != nil {
		return deviceCredential{}, fmt.Errorf("norton onboard: activate: %w", err)
	}
	if status != http.StatusOK {
		return deviceCredential{}, fmt.Errorf("norton onboard: activate: status %d", status)
	}
	// activate answers HTTP 200 even on failure, carrying the same error envelope
	// the other calls use (for example code -5044 when the seat cannot be issued a
	// credential, or a registration error). Surface it here so the real reason
	// shows instead of a misleading empty-credential result.
	if err := checkEnvelope(body); err != nil {
		return deviceCredential{}, fmt.Errorf("norton onboard: activate: %w", err)
	}
	cred, err := extractVPNPassage(body)
	if err != nil {
		return deviceCredential{}, fmt.Errorf("norton onboard: activate: %w", err)
	}
	return cred, nil
}

// extractVPNPassage pulls the device credential out of an activate jobs array.
// The response is {"data":[[ job, ... ]]}, one job carrying a vpn_passage block
// whose response.data.credentials holds the OpenVPN username (device_udid),
// password and CA.
func extractVPNPassage(body []byte) (deviceCredential, error) {
	var out struct {
		Data [][]struct {
			Job  string          `json:"Job"`
			Data json.RawMessage `json:"Data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return deviceCredential{}, fmt.Errorf("decode: %w", err)
	}
	for _, group := range out.Data {
		for _, job := range group {
			if !bytes.Contains(job.Data, []byte("vpn_passage")) {
				continue
			}
			var wrap struct {
				VPNPassage struct {
					Response struct {
						Data struct {
							Credentials struct {
								DeviceUDID     string `json:"device_udid"`
								DevicePassword string `json:"device_password"`
								OpenVPNCA      string `json:"openvpn_ca_certificate"`
							} `json:"credentials"`
						} `json:"data"`
					} `json:"response"`
				} `json:"vpn_passage"`
			}
			if err := json.Unmarshal(job.Data, &wrap); err != nil {
				continue
			}
			cr := wrap.VPNPassage.Response.Data.Credentials
			if cr.DeviceUDID != "" {
				return deviceCredential{
					Username: cr.DeviceUDID,
					Password: cr.DevicePassword,
					CA:       strings.TrimSpace(cr.OpenVPNCA),
				}, nil
			}
		}
	}
	return deviceCredential{}, fmt.Errorf("carried no vpn_passage credential (seat unavailable?)")
}

// postJSON sends a JSON body to a /ccapi endpoint and decodes the response.
func (c *onboardClient) postJSON(ctx context.Context, path string, payload, out any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	c.apiHeaders(req, true)
	body, status, err := c.do(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d", status)
	}
	if err := checkEnvelope(body); err != nil {
		return err
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
	}
	return nil
}

// brStripper turns the <br> variants the cloudconnect messages carry into
// spaces so the surfaced error reads as one line.
var brStripper = strings.NewReplacer("<br>", " ", "<br/>", " ", "<br />", " ")

// checkEnvelope surfaces the cloudconnect error envelope. Every /ccapi call
// answers HTTP 200 even when it fails, carrying
// {"success":false,"error":{"code":...,"additionalinfo":{...}}} (for example
// code -500 "Server error ... Try again later" when the product context is
// missing or the key/account cannot be served), so the status code alone never
// reveals a rejection. Returning the server's own code and message here makes a
// block report at the step that actually failed instead of surfacing later as a
// misleading empty result.
func checkEnvelope(body []byte) error {
	var env struct {
		Success *bool `json:"success"`
		Error   *struct {
			Code           int `json:"code"`
			AdditionalInfo struct {
				Header  string `json:"header"`
				Content string `json:"content"`
			} `json:"additionalinfo"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		// Not the common envelope shape; let the caller decode its own body.
		return nil
	}
	if env.Error == nil && (env.Success == nil || *env.Success) {
		return nil
	}
	code := 0
	msg := ""
	if env.Error != nil {
		code = env.Error.Code
		header := strings.TrimSpace(env.Error.AdditionalInfo.Header)
		content := strings.TrimSpace(brStripper.Replace(env.Error.AdditionalInfo.Content))
		switch {
		case header != "" && content != "":
			msg = header + ": " + content
		case header != "":
			msg = header
		default:
			msg = content
		}
	}
	if msg == "" {
		msg = "request rejected"
	}
	return fmt.Errorf("server error %d: %s", code, msg)
}

// secChUA is the WebView client-hint brand list; the backend's bot checks reject
// /ccapi calls that lack the Chromium/WebView fingerprint the app sends.
const secChUA = `"Not_A Brand";v="8", "Chromium";v="120", "Android WebView";v="120"`

// apiHeaders sets the headers every /ccapi call carries. The antiforgery token
// and the cookie jar together authorise the call; there is no bearer token. The
// sec-ch-ua / Sec-Fetch client hints mirror the in-app WebView so the request is
// not turned away before it reaches the controller.
func (c *onboardClient) apiHeaders(req *http.Request, json bool) {
	req.Header.Set("User-Agent", onboardUA)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("X-Requested-With", appPackage)
	req.Header.Set("Origin", c.base)
	req.Header.Set("Referer", fmt.Sprintf("%s/cloudconnect/home/?gentraceid=%s", c.base, c.traceID))
	req.Header.Set("Sec-Ch-Ua", secChUA)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?1")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Android"`)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("X-Frame-Options", "SAMEORIGIN")
	if c.xsrfToken != "" {
		req.Header.Set("X-XSRF-Token", c.xsrfToken)
	}
	if json {
		req.Header.Set("Content-Type", "application/json")
	}
}

func (c *onboardClient) do(req *http.Request) ([]byte, int, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func machineName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "tundler-norton"
}

// randomSerial returns a decimal serial for the issued client certificate; the
// backend records it but it does not gate the OpenVPN user/pass path.
func randomSerial() string {
	var sb strings.Builder
	for i := 0; i < 38; i++ {
		if i == 0 {
			sb.WriteByte(byte('1' + rand.Intn(9)))
			continue
		}
		sb.WriteByte(byte('0' + rand.Intn(10)))
	}
	return sb.String()
}
