package main

// Headless discovery-token refresh.
//
// The SurfEasy discovery JWT is short-lived (~12h) and its renew endpoint is a
// dead end, but the Norton cloudconnect backend mints a fresh one on demand with
// a single silent call that is authenticated only by the device identity and the
// license ids (no cookie, no OAuth, no session, no sign-in, and no seat use):
//
//	POST https://cloudconnect2.norton.com/cloudconnect/silent/v2/RefreshServiceResponse
//
// The response carries a vpn_passage block whose data.token.access_token is a
// fresh Bearer JWT for the discovery API. All of the identity/license inputs are
// static per seat (captured once at provisioning), so a scheduled job can refresh
// the catalog unattended. The runtime tunnel still needs none of this.
//
// Inputs (from the environment, delivered from the secret store by the workflow):
//
//	NORTON_FINGERPRINT          device fingerprint (uppercase hex, 8 bytes)
//	NORTON_ENDPOINT_ID          device endpoint id (canonical UUID)
//	NORTON_LICENSE_PSN          the seat's product serial
//	NORTON_LICENSE_CONSUMER_ID  the account/consumer id
//	NORTON_LICENSE_PRODUCT_SKU  the product SKU
//	NORTON_CERTIFICATE_SERIAL   the device's registered client-cert serial
//	NORTON_PARTNER_ID           partner id (default 1000)
//	NORTON_PARTNER_UNIT_ID      partner unit id (default 5039)
//	NORTON_TENANT_ID            cloudconnect tenant id (default: the baked NortonGen tenant)

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	cloudConnectBase   = "https://cloudconnect2.norton.com"
	silentRefreshPath  = "/cloudconnect/silent/v2/RefreshServiceResponse"
	defaultTenantID    = "de527324-05e3-46eb-a2a7-43ab29c1aff7"
	defaultPartnerID   = "1000"
	defaultPartnerUnit = 5039
	refreshUserAgent   = "Ktor client"
)

// refreshDiscoveryToken mints a fresh discovery Bearer JWT via the cloudconnect
// silent refresh. It returns the access token from the vpn_passage block.
func refreshDiscoveryToken(ctx context.Context, hc *http.Client) (string, error) {
	fingerprint := strings.TrimSpace(os.Getenv("NORTON_FINGERPRINT"))
	endpointID := strings.TrimSpace(os.Getenv("NORTON_ENDPOINT_ID"))
	psn := strings.TrimSpace(os.Getenv("NORTON_LICENSE_PSN"))
	consumerID := strings.TrimSpace(os.Getenv("NORTON_LICENSE_CONSUMER_ID"))
	productSKU := strings.TrimSpace(os.Getenv("NORTON_LICENSE_PRODUCT_SKU"))
	// The backend validates certificateserial against the device's registered
	// client certificate; a wrong/random value is rejected with a misleading
	// "JsonEncodingError" (-727). It is a static seed captured at provisioning.
	certSerial := strings.TrimSpace(os.Getenv("NORTON_CERTIFICATE_SERIAL"))
	if fingerprint == "" || endpointID == "" || psn == "" || consumerID == "" || productSKU == "" || certSerial == "" {
		return "", fmt.Errorf("headless refresh needs NORTON_FINGERPRINT, NORTON_ENDPOINT_ID, NORTON_LICENSE_PSN, NORTON_LICENSE_CONSUMER_ID, NORTON_LICENSE_PRODUCT_SKU and NORTON_CERTIFICATE_SERIAL")
	}
	tenantID := envOr("NORTON_TENANT_ID", defaultTenantID)
	partnerID := envOr("NORTON_PARTNER_ID", defaultPartnerID)
	partnerUnit := defaultPartnerUnit
	if v := strings.TrimSpace(os.Getenv("NORTON_PARTNER_UNIT_ID")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			partnerUnit = n
		}
	}

	clientCustomData, _ := json.Marshal(map[string]any{
		"authonlyprovidepi": false,
		"certificateserial": certSerial,
	})
	b2bs, _ := json.Marshal([]map[string]any{{
		"service": "vpn_passage",
		"payload": map[string]string{"clientVersion": "26.20.0", "clientType": clientType},
	}})
	body := map[string]any{
		"Action":                    "RefreshServiceResponse",
		"OSLocale":                  "US",
		"OSLanguage":                "en",
		"Fingerprint":               fingerprint,
		"EndPointId":                endpointID,
		"MachineName":               "Google_sdk_gphone64_x86_64",
		"ManufacturerModel":         "sdk_gphone64_x86_64",
		"ManufacturerName":          "Google",
		"Country":                   "us",
		"ApplicationMajorVersionId": "2846",
		"LayoutProductLanguage":     "en",
		"LayoutXlokSKU":             3690,
		"LayoutMediaSKU":            "21366757",
		"SchemaCategory":            "SBU_MOBILE",
		"SchemaVersion":             "2.0.0.0",
		"RequesterIds":              "https://accesstoken.securevpn.norton.com",
		"ClientCustomData":          string(clientCustomData),
		"B2Bs":                      string(b2bs),
		"LicenseConsumerId":         consumerID,
		"LicenseProductSKU":         productSKU,
		"LicensePSN":                psn,
		"PartnerId":                 partnerID,
		"PartnerUnitId":             partnerUnit,
		"ClientData":                newUUID(),
		"SiloId":                    "",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	if os.Getenv("NORTON_REFRESH_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "norton-updater: refresh request body: %s\n", string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cloudConnectBase+silentRefreshPath, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Charset", "UTF-8")
	req.Header.Set("User-Agent", refreshUserAgent)
	// Setting Accept-Encoding ourselves disables Go's automatic gzip (and its
	// transparent decompression). The backend's request parser rejects the call
	// with JsonEncodingError when the transport advertises gzip the way Go does;
	// identity matches a plain client and is accepted.
	req.Header.Set("Accept-Encoding", "identity")
	// Send the NLOK/SYMC headers in the app's exact uppercase form. Assigning to
	// the map directly bypasses Go's header canonicalization (which would send
	// X-Symc-User-Agent); the backend wants X-SYMC-USER-AGENT.
	req.Header["X-SYMC-USER-AGENT"] = []string{"NSV/" + clientVersion + "/Android/12"}
	req.Header["X-NLOK-TENANT-ID"] = []string{tenantID}
	req.Header["X-NLOK-TRACE-ID"] = []string{newUUID()}

	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("silent refresh: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	token, err := extractPassageToken(respBody)
	if err != nil {
		if os.Getenv("NORTON_REFRESH_DEBUG") == "1" {
			head := respBody
			if len(head) > 400 {
				head = head[:400]
			}
			fmt.Fprintf(os.Stderr, "norton-updater: refresh response head: %s\n", string(head))
		}
		return "", fmt.Errorf("silent refresh: %w", err)
	}
	return token, nil
}

// extractPassageToken pulls data[].Data.vpn_passage.response.data.token.access_token
// out of a RefreshServiceResponse body.
func extractPassageToken(body []byte) (string, error) {
	var out struct {
		Data []struct {
			Data json.RawMessage `json:"Data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	for _, job := range out.Data {
		if !bytes.Contains(job.Data, []byte("vpn_passage")) {
			continue
		}
		var wrap struct {
			VPNPassage struct {
				Response struct {
					Data struct {
						Token struct {
							AccessToken string `json:"access_token"`
						} `json:"token"`
					} `json:"data"`
				} `json:"response"`
			} `json:"vpn_passage"`
		}
		if err := json.Unmarshal(job.Data, &wrap); err != nil {
			continue
		}
		if t := wrap.VPNPassage.Response.Data.Token.AccessToken; t != "" {
			return t, nil
		}
	}
	return "", fmt.Errorf("response carried no vpn_passage access_token")
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func newUUID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		for i := range b {
			b[i] = byte(rand.Intn(256))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}

