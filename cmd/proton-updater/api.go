package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"

	srp "github.com/ProtonMail/go-srp"
)

// Proton's account API rejects requests that don't claim a recent
// app version. Pin a "Proton Mail Web" version that's safely in
// range; updating this is rarely needed (we only bump it if Proton
// starts rejecting the constant). Sourced manually rather than via a
// GitHub tags lookup to keep this tool self-contained — gluetun does
// the lookup live, which is one more failure mode than we need here.
const protonAppVersion = "web-account@5.0.999.0"

// Pick a random plausible browser UA per run so any per-UA throttling
// at Proton's edge doesn't gradually paint our updater into a corner.
var userAgents = [...]string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0",
}

type apiClient struct {
	base      string
	http      *http.Client
	userAgent string
	rng       *rand.ChaCha8
}

// cookieState carries the four pieces of session state Proton expects
// stitched together on every authenticated request: the session ID
// (set as Session-Id cookie by /vpn page load), the UID + access
// token (returned by the unauthenticated session endpoint), and the
// final cookie-token (set by the /auth/cookies exchange). After full
// SRP login the auth cookie supersedes the unauth bearer; we still
// keep UID + sessionID since they're echoed as headers.
type cookieState struct {
	sessionID string
	uid       string
	token     string // bearer-style cookie token, suitable for the Cookie: AUTH-…= header
}

func (c cookieState) header() string {
	parts := []string{}
	if c.sessionID != "" {
		parts = append(parts, "Session-Id="+c.sessionID)
	}
	if c.token != "" {
		parts = append(parts, "AUTH-"+c.uid+"="+c.token)
	}
	return strings.Join(parts, "; ")
}

func newAPIClient(ctx context.Context) (*apiClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookiejar: %w", err)
	}
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("seed rng: %w", err)
	}
	rng := rand.NewChaCha8(seed)

	hc := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
	}
	return &apiClient{
		base:      "https://account.proton.me/api",
		http:      hc,
		userAgent: userAgents[rng.Uint64()%uint64(len(userAgents))],
		rng:       rng,
	}, nil
}

// setHeaders attaches the headers Proton's account API checks for on
// every request. Skipping any of these gets a 4xx with no hint as to
// which header the rejection is about; we set them all.
func (c *apiClient) setHeaders(req *http.Request, cookie cookieState) {
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("x-pm-appversion", protonAppVersion)
	req.Header.Set("x-pm-locale", "en_US")
	if cookie.uid != "" {
		req.Header.Set("x-pm-uid", cookie.uid)
	}
	if h := cookie.header(); h != "" {
		req.Header.Set("Cookie", h)
	}
	req.Header.Set("Accept", "application/json")
}

// authenticate runs the full SRP login dance and returns a cookie
// ready for /vpn/v1/logicals. Steps:
//  1. GET /vpn → drops a Session-Id cookie.
//  2. POST /auth/v4/sessions → unauthenticated access token + UID.
//  3. POST /core/v4/auth/cookies → exchange access+refresh for an
//     opaque cookie token (still unauthenticated).
//  4. GET /core/v4/auth/info → SRP modulus, salt, server-ephemeral,
//     and the version the account is registered against.
//  5. SRP proof generation (using github.com/ProtonMail/go-srp,
//     which implements Proton's hash variants).
//  6. POST /core/v4/auth → submit proof, get authenticated UID +
//     access token + new cookie token.
func (c *apiClient) authenticate(ctx context.Context, email, password string) (cookieState, error) {
	sessionID, err := c.fetchSessionID(ctx)
	if err != nil {
		return cookieState{}, fmt.Errorf("session id: %w", err)
	}

	tokenType, accessToken, refreshToken, uid, err := c.fetchUnauthSession(ctx, sessionID)
	if err != nil {
		return cookieState{}, fmt.Errorf("unauth session: %w", err)
	}

	unauth := cookieState{sessionID: sessionID, uid: uid}

	cookieToken, err := c.exchangeForCookieToken(ctx, unauth, tokenType, accessToken, refreshToken)
	if err != nil {
		return cookieState{}, fmt.Errorf("cookie token: %w", err)
	}
	unauth.token = cookieToken

	info, err := c.fetchAuthInfo(ctx, unauth, email)
	if err != nil {
		return cookieState{}, fmt.Errorf("auth info: %w", err)
	}

	srpAuth, err := srp.NewAuth(info.Version, email, []byte(password),
		info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		return cookieState{}, fmt.Errorf("srp init: %w", err)
	}
	proofs, err := srpAuth.GenerateProofs(2048)
	if err != nil {
		return cookieState{}, fmt.Errorf("srp proofs: %w", err)
	}

	authed, err := c.submitAuth(ctx, unauth, email, info.SRPSession, proofs)
	if err != nil {
		return cookieState{}, fmt.Errorf("auth submit: %w", err)
	}
	return authed, nil
}

// -----------------------------------------------------------------
// Step 1 — GET /vpn for the Session-Id cookie
// -----------------------------------------------------------------

func (c *apiClient) fetchSessionID(ctx context.Context) (string, error) {
	const url = "https://account.proton.me/vpn"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "Session-Id" {
			return cookie.Value, nil
		}
	}
	return "", errors.New("Session-Id cookie missing in /vpn response")
}

// -----------------------------------------------------------------
// Step 2 — POST /auth/v4/sessions for unauthenticated access tokens
// -----------------------------------------------------------------

type unauthSessionResponse struct {
	Code         uint   `json:"Code"`
	AccessToken  string `json:"AccessToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"TokenType"`
	UID          string `json:"UID"`
}

func (c *apiClient) fetchUnauthSession(ctx context.Context, sessionID string) (tokenType, accessToken, refreshToken, uid string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/auth/v4/sessions", http.NoBody)
	if err != nil {
		return "", "", "", "", err
	}
	c.setHeaders(req, cookieState{sessionID: sessionID})

	var resp unauthSessionResponse
	if err := c.doJSON(req, &resp); err != nil {
		return "", "", "", "", err
	}
	if resp.Code != 1000 {
		return "", "", "", "", fmt.Errorf("unexpected code %d", resp.Code)
	}
	return resp.TokenType, resp.AccessToken, resp.RefreshToken, resp.UID, nil
}

// -----------------------------------------------------------------
// Step 3 — POST /core/v4/auth/cookies to exchange tokens for a cookie
// -----------------------------------------------------------------

type cookieTokenRequest struct {
	GrantType    string `json:"GrantType"`
	Persistent   uint   `json:"Persistent"`
	RedirectURI  string `json:"RedirectURI"`
	RefreshToken string `json:"RefreshToken"`
	ResponseType string `json:"ResponseType"`
	State        string `json:"State"`
	UID          string `json:"UID"`
}

type cookieTokenResponse struct {
	Code uint   `json:"Code"`
	UID  string `json:"UID"`
}

func (c *apiClient) exchangeForCookieToken(ctx context.Context, cookie cookieState, tokenType, accessToken, refreshToken string) (string, error) {
	body := cookieTokenRequest{
		GrantType:    "refresh_token",
		Persistent:   0,
		RedirectURI:  "https://protonmail.com",
		RefreshToken: refreshToken,
		ResponseType: "token",
		State:        c.randomState(24),
		UID:          cookie.uid,
	}
	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(body); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/core/v4/auth/cookies", buf)
	if err != nil {
		return "", err
	}
	c.setHeaders(req, cookie)
	req.Header.Set("Authorization", tokenType+" "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", apiError(resp.StatusCode, respBody)
	}

	var parsed cookieTokenResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("decode: %w (body=%q)", err, snippet(respBody))
	}
	if parsed.Code != 1000 {
		return "", fmt.Errorf("unexpected code %d (body=%q)", parsed.Code, snippet(respBody))
	}

	// The cookie token comes back as a Set-Cookie named AUTH-<UID>.
	for _, ck := range resp.Cookies() {
		if strings.HasPrefix(ck.Name, "AUTH-") {
			return ck.Value, nil
		}
	}
	return "", errors.New("AUTH-<UID> cookie missing in /auth/cookies response")
}

// -----------------------------------------------------------------
// Step 4 — POST /core/v4/auth/info for SRP parameters
// -----------------------------------------------------------------

type authInfo struct {
	Modulus         string `json:"Modulus"`
	ServerEphemeral string `json:"ServerEphemeral"`
	Salt            string `json:"Salt"`
	SRPSession      string `json:"SRPSession"`
	Version         int    `json:"Version"`
	Code            uint   `json:"Code"`
}

func (c *apiClient) fetchAuthInfo(ctx context.Context, cookie cookieState, email string) (*authInfo, error) {
	body, err := json.Marshal(struct {
		Username string `json:"Username"`
	}{Username: email})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/core/v4/auth/info", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.setHeaders(req, cookie)
	req.Header.Set("Content-Type", "application/json")

	var info authInfo
	if err := c.doJSON(req, &info); err != nil {
		return nil, err
	}
	if info.Code != 1000 {
		return nil, fmt.Errorf("auth info code %d", info.Code)
	}
	return &info, nil
}

// -----------------------------------------------------------------
// Step 5 — POST /core/v4/auth (submit SRP proofs)
// -----------------------------------------------------------------

type authRequest struct {
	Username        string `json:"Username"`
	ClientEphemeral string `json:"ClientEphemeral"`
	ClientProof     string `json:"ClientProof"`
	SRPSession      string `json:"SRPSession"`
}

type authResponse struct {
	Code         uint   `json:"Code"`
	UID          string `json:"UID"`
	AccessToken  string `json:"AccessToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"TokenType"`
	ServerProof  string `json:"ServerProof"`
}

func (c *apiClient) submitAuth(ctx context.Context, cookie cookieState, email, srpSession string, proofs *srp.Proofs) (cookieState, error) {
	body, err := json.Marshal(authRequest{
		Username:        email,
		ClientEphemeral: base64Encode(proofs.ClientEphemeral),
		ClientProof:     base64Encode(proofs.ClientProof),
		SRPSession:      srpSession,
	})
	if err != nil {
		return cookieState{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/core/v4/auth", bytes.NewReader(body))
	if err != nil {
		return cookieState{}, err
	}
	c.setHeaders(req, cookie)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return cookieState{}, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return cookieState{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return cookieState{}, apiError(resp.StatusCode, respBody)
	}

	var parsed authResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return cookieState{}, fmt.Errorf("decode auth: %w (body=%q)", err, snippet(respBody))
	}
	if parsed.Code != 1000 {
		return cookieState{}, fmt.Errorf("auth code %d (body=%q)", parsed.Code, snippet(respBody))
	}

	authed := cookieState{
		sessionID: cookie.sessionID,
		uid:       parsed.UID,
	}
	for _, ck := range resp.Cookies() {
		if strings.HasPrefix(ck.Name, "AUTH-") {
			authed.token = ck.Value
			break
		}
	}
	if authed.token == "" {
		// Some responses set the auth cookie only via the
		// follow-up /auth/cookies; if so, use the access token
		// directly in a synthetic AUTH cookie (Proton accepts it).
		authed.token = parsed.AccessToken
	}
	return authed, nil
}

// -----------------------------------------------------------------
// Step 6 — GET /vpn/v1/logicals
// -----------------------------------------------------------------

type physicalServer struct {
	ID        string `json:"ID"`
	Domain    string `json:"Domain"`
	EntryIP   string `json:"EntryIP"`
	Status    int    `json:"Status"`
	Generation int   `json:"Generation"`
}

type logicalServer struct {
	Name        string           `json:"Name"`
	EntryCountry string          `json:"EntryCountry"`
	ExitCountry string           `json:"ExitCountry"`
	Country     string           `json:"Country"`
	Region      string           `json:"Region"`
	City        string           `json:"City"`
	Tier        *int             `json:"Tier"`
	Features    int              `json:"Features"`
	Servers     []physicalServer `json:"Servers"`
	Status      int              `json:"Status"`
}

type logicalsResponse struct {
	Code           uint            `json:"Code"`
	LogicalServers []logicalServer `json:"LogicalServers"`
}

func (c *apiClient) fetchLogicals(ctx context.Context, cookie cookieState) (*logicalsResponse, error) {
	// Proton's /vpn/v1/logicals returns Type=1 (standard) servers by
	// default — the gated SecureCore tier (Type=2) is only included
	// when explicitly requested. Plus-tier accounts include
	// SecureCore in their plan but the API still filters by Type. Hit
	// both endpoints and merge, deduplicating by logical-server ID
	// when present (Name is the readable identifier and stays stable
	// across both responses).
	standard, err := c.fetchLogicalsForType(ctx, cookie, 0)
	if err != nil {
		return nil, err
	}
	secureCore, err := c.fetchLogicalsForType(ctx, cookie, 2)
	if err != nil {
		// SecureCore probe is best-effort — Plus account is required,
		// and Proton may have changed the Type param semantics. Log
		// loudly to stderr but proceed with whatever we have so we
		// don't break the standard-tier refresh on a SecureCore
		// probe error.
		fmt.Fprintf(os.Stderr, "proton-updater: SecureCore probe failed (?Type=2): %v — continuing with standard tier only\n", err)
		return standard, nil
	}
	merged := mergeLogicals(standard, secureCore)
	fmt.Fprintf(os.Stderr, "proton-updater: fetched %d standard + %d secure-core (after merge: %d unique logicals)\n",
		len(standard.LogicalServers), len(secureCore.LogicalServers), len(merged.LogicalServers))
	return merged, nil
}

func (c *apiClient) fetchLogicalsForType(ctx context.Context, cookie cookieState, serverType int) (*logicalsResponse, error) {
	url := c.base + "/vpn/v1/logicals"
	if serverType > 0 {
		url += fmt.Sprintf("?Type=%d", serverType)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req, cookie)

	var resp logicalsResponse
	if err := c.doJSON(req, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 1000 {
		return nil, fmt.Errorf("logicals code %d", resp.Code)
	}
	return &resp, nil
}

// mergeLogicals deduplicates by Name (stable Proton-side identifier
// like "IS#1" or "SE-CH#3"). When the same Name appears in both
// responses, the SecureCore response wins so the Features bitfield
// reflects the most specific tier classification.
func mergeLogicals(standard, secureCore *logicalsResponse) *logicalsResponse {
	out := &logicalsResponse{Code: 1000}
	seen := make(map[string]int, len(standard.LogicalServers)+len(secureCore.LogicalServers))
	for _, ls := range standard.LogicalServers {
		seen[ls.Name] = len(out.LogicalServers)
		out.LogicalServers = append(out.LogicalServers, ls)
	}
	for _, ls := range secureCore.LogicalServers {
		if idx, ok := seen[ls.Name]; ok {
			out.LogicalServers[idx] = ls // SecureCore response wins on dupes
			continue
		}
		seen[ls.Name] = len(out.LogicalServers)
		out.LogicalServers = append(out.LogicalServers, ls)
	}
	return out
}

// -----------------------------------------------------------------
// shared helpers
// -----------------------------------------------------------------

func (c *apiClient) doJSON(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return apiError(resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s %s: %w (body=%q)", req.Method, req.URL.Path, err, snippet(body))
	}
	return nil
}

func apiError(status int, body []byte) error {
	// Surface Proton's Code/Error pair when present so the workflow
	// log says exactly what went wrong (e.g. 8002 = wrong password,
	// 12087 = human verification required).
	var parsed struct {
		Code  uint   `json:"Code"`
		Error string `json:"Error"`
	}
	if json.Unmarshal(body, &parsed) == nil && (parsed.Code != 0 || parsed.Error != "") {
		return fmt.Errorf("HTTP %d: code=%d %s", status, parsed.Code, parsed.Error)
	}
	return fmt.Errorf("HTTP %d: %s", status, snippet(body))
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func (c *apiClient) randomState(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[c.rng.Uint64()%uint64(len(letters))]
	}
	return string(b)
}

func snippet(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "…"
	}
	return string(b)
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
