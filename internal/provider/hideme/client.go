package hideme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// controlClient talks to the official hide.me client running in service
// mode (`hide.me service`), which exposes a small REST API on a UNIX
// socket. Every reply is a JSON-RPC style object: {"result": ...} on
// success, {"error": {"code": ..., "message": ...}} on failure.
type controlClient struct {
	http *http.Client
}

func newControlClient(socket string) *controlClient {
	return &controlClient{http: &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}}
}

// rpcError is an error the service reported in its reply.
type rpcError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	if e.Message == "" {
		return "hide.me service: " + e.Code
	}
	return "hide.me service: " + e.Code + ": " + e.Message
}

type rpcReply struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// errBusy is the service's 409: another operation held its lock for
// more than a second.
var errBusy = errors.New("hide.me service busy")

// call sends one request and decodes the reply's result into out (when
// out is non-nil). A busy service is retried a few times.
func (c *controlClient) call(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		err = c.once(ctx, method, path, payload, out)
		if !errors.Is(err, errBusy) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return err
}

func (c *controlClient) once(ctx context.Context, method, path string, payload []byte, out any) error {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://hide.me"+path, reader)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusConflict {
		return errBusy
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hide.me service %s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out == nil {
		// Still surface a reported error.
		var reply rpcReply
		if json.Unmarshal(raw, &reply) == nil && reply.Error != nil {
			return reply.Error
		}
		return nil
	}
	if s, ok := out.(*string); ok && len(raw) > 0 && raw[0] != '{' {
		// /version answers with the bare version string.
		*s = string(bytes.TrimSpace(raw))
		return nil
	}
	var reply rpcReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return fmt.Errorf("hide.me service %s %s: decode reply: %w", method, path, err)
	}
	if reply.Error != nil {
		return reply.Error
	}
	if len(reply.Result) == 0 {
		return nil
	}
	return json.Unmarshal(reply.Result, out)
}

// connState is the subset of the service's state object read here.
type connState struct {
	Code string `json:"code"`
}

func (c *controlClient) state(ctx context.Context) (string, error) {
	var st connState
	if err := c.call(ctx, http.MethodGet, "/state", nil, &st); err != nil {
		return "", err
	}
	return st.Code, nil
}

func (c *controlClient) version(ctx context.Context) (string, error) {
	var v string
	err := c.call(ctx, http.MethodGet, "/version", nil, &v)
	return v, err
}

// requestToken asks the service for an Access-Token with the account
// login. The service uses the login for this request only and keeps it
// neither in its configuration nor in its log.
func (c *controlClient) requestToken(ctx context.Context, host, username, password string) (string, error) {
	var token string
	err := c.call(ctx, http.MethodPost, "/requestToken", map[string]string{
		"Host":     host,
		"Username": username,
		"Password": password,
	}, &token)
	return token, err
}

// setHost points the next connect at host. The service logs the body of
// a configuration request, so nothing secret may ever go through here.
func (c *controlClient) setHost(ctx context.Context, host string) error {
	return c.call(ctx, http.MethodPost, "/configuration", map[string]any{
		"Rest": map[string]string{"Host": host},
	}, nil)
}

func (c *controlClient) connect(ctx context.Context) error {
	var st connState
	if err := c.call(ctx, http.MethodGet, "/connect", nil, &st); err != nil {
		return err
	}
	if st.Code != "connected" {
		return fmt.Errorf("hide.me service: connect ended in state %q", st.Code)
	}
	return nil
}

func (c *controlClient) disconnect(ctx context.Context) error {
	return c.call(ctx, http.MethodGet, "/disconnect", nil, nil)
}

// destroy disconnects and removes the interface, routes and rules.
func (c *controlClient) destroy(ctx context.Context) error {
	return c.call(ctx, http.MethodGet, "/destroy", nil, nil)
}
