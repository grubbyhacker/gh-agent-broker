package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// capHeader is the dedicated request header carrying a run's opaque per-run
// capability handle on pull.create. Authorization is already occupied by the
// agent's own credential (which authorizes the GitHub repo/operation), so the
// capability handle — which establishes the originating run/WorkItem identity —
// travels here instead. The plaintext handle is used only to verify against the
// broker's private capability API and is never logged, audited, persisted, or
// written into metadata.
const capHeader = "X-Agent-Capability"

// capMaxResponseBytes bounds a capability API response body (a tiny JSON claims
// object); the cap is a hard backstop.
const capMaxResponseBytes = 8 * 1024

// Capability verification outcomes. The handler maps these to HTTP status; none
// ever carries the plaintext handle.
var (
	// errCapMissing: correlation is enabled but the request presented no handle.
	errCapMissing = errors.New("capability handle is required")
	// errCapDenied: a definite negative verdict from the capability API
	// (unknown/malformed/revoked/expired/invalid). Fail closed.
	errCapDenied = errors.New("capability denied")
	// errCapUnavailable: the capability API could not be reached or errored at
	// the transport/5xx level. Fail closed — an unverifiable run is not correlated.
	errCapUnavailable = errors.New("capability API unavailable")
)

// verifiedCapability is the trusted run identity derived solely from the
// capability API's verify response. The handler uses these values in place of
// any caller-supplied metadata/run_id.
type verifiedCapability struct {
	AgentType  string
	Mode       string
	RunID      string
	WorkItemID string
}

func (v verifiedCapability) complete() bool {
	return v.AgentType != "" && v.Mode != "" && v.RunID != "" && v.WorkItemID != ""
}

// capVerifier verifies opaque capability handles against the broker's PRIVATE
// capability API. It authenticates with a deployment-owned static token held
// only by the broker (NOT any run's handle) and sends the handle only in the
// request body.
type capVerifier struct {
	baseURL string
	token   string
	http    *http.Client
}

func newCapVerifier(baseURL, token string, timeout time.Duration, transport http.RoundTripper) *capVerifier {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	if transport != nil {
		client.Transport = transport
	}
	return &capVerifier{baseURL: strings.TrimRight(baseURL, "/"), token: token, http: client}
}

type capVerifyRequest struct {
	Handle string `json:"handle"`
}

type capVerifyResponse struct {
	AgentType  string `json:"agent_type"`
	Mode       string `json:"mode"`
	RunID      string `json:"run_id"`
	WorkItemID string `json:"work_item_id"`
}

// verify authenticates the opaque handle against the broker and returns the
// trusted run identity. It fails closed: a transport error or 5xx becomes
// errCapUnavailable, a 4xx becomes errCapDenied, and the handle is never
// included in any returned error.
func (c *capVerifier) verify(ctx context.Context, handle string) (verifiedCapability, error) {
	payload, err := json.Marshal(capVerifyRequest{Handle: handle})
	if err != nil {
		return verifiedCapability{}, fmt.Errorf("%w: encode request", errCapUnavailable)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/capabilities/verify", bytes.NewReader(payload))
	if err != nil {
		return verifiedCapability{}, fmt.Errorf("%w: build request", errCapUnavailable)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		cause := err
		if ctx.Err() != nil {
			cause = ctx.Err()
		}
		return verifiedCapability{}, fmt.Errorf("%w: %s", errCapUnavailable, cause.Error())
	}
	defer closeBody(resp.Body)
	body, err := io.ReadAll(io.LimitReader(resp.Body, capMaxResponseBytes))
	if err != nil {
		return verifiedCapability{}, fmt.Errorf("%w: read response", errCapUnavailable)
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		var out capVerifyResponse
		if err := json.Unmarshal(body, &out); err != nil {
			return verifiedCapability{}, fmt.Errorf("%w: decode response", errCapDenied)
		}
		v := verifiedCapability(out)
		if !v.complete() {
			return verifiedCapability{}, fmt.Errorf("%w: incomplete claims", errCapDenied)
		}
		return v, nil
	case resp.StatusCode >= 500:
		return verifiedCapability{}, fmt.Errorf("%w: status %d", errCapUnavailable, resp.StatusCode)
	default:
		return verifiedCapability{}, fmt.Errorf("%w: status %d", errCapDenied, resp.StatusCode)
	}
}

// capStatus maps a verification error to an HTTP status and a stable,
// handle-free error code.
func capStatus(err error) (int, string) {
	switch {
	case errors.Is(err, errCapMissing):
		return http.StatusUnauthorized, "capability_required"
	case errors.Is(err, errCapUnavailable):
		return http.StatusServiceUnavailable, "capability_unavailable"
	default:
		return http.StatusForbidden, "capability_denied"
	}
}
