package proxy

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

// capMaxResponseBytes bounds a capability API response body. The verify/reserve
// responses are tiny JSON objects; the cap is a hard backstop against a
// misbehaving or spoofed API endpoint.
const capMaxResponseBytes = 8 * 1024

// Capability enforcement errors. These are the categories the proxy maps to HTTP
// status codes and audits. None ever carries the plaintext handle.
var (
	// errCapMissing is returned when capability enforcement is enabled but the
	// request presented no handle.
	errCapMissing = errors.New("capability handle is required")
	// errCapDenied covers every negative verdict from the capability API:
	// unknown/malformed/revoked/expired handle, model denial, budget
	// exhaustion, invalid claims. Fail closed: the proxy never distinguishes
	// these to the caller beyond a bounded status.
	errCapDenied = errors.New("capability denied")
	// errCapUnavailable is returned when the capability API cannot be reached or
	// answers with a transport/5xx error. Fail closed: an unreachable authority
	// denies the call rather than forwarding it.
	errCapUnavailable = errors.New("capability API unavailable")
	// errCapIdentityMismatch is returned when a legacy caller-provided identity
	// field (body run_id or X-GH-Agent-Run-ID header) is present and disagrees
	// with the verified claim. The proxy stops trusting caller identity and
	// rejects a mismatch rather than silently overriding it.
	errCapIdentityMismatch = errors.New("caller-provided run_id does not match the verified capability")
)

// capClaims is the trusted, broker-verified identity and policy for a run,
// derived solely from the capability API's verify response. The proxy uses these
// values in place of any caller-asserted run_id/agent_type/mode/work_item_id.
type capClaims struct {
	AgentType      string
	Mode           string
	RunID          string
	WorkItemID     string
	AllowedModels  []string
	CallBudget     int64
	TokenBudget    int64
	Expiry         time.Time
	ReservedCalls  int64
	ReservedTokens int64
}

// modelEnabled reports whether the capability grants any model access. A
// model-disabled capability (empty allowed_models, zero budgets) may not make
// any model-proxy call.
func (c capClaims) modelEnabled() bool { return len(c.AllowedModels) > 0 }

// allowsModel reports whether model is in the verified allowed set.
func (c capClaims) allowsModel(model string) bool {
	for _, m := range c.AllowedModels {
		if m == model {
			return true
		}
	}
	return false
}

// capClient is the proxy's client for the broker's PRIVATE capability
// verify/reserve API. It authenticates with a static bearer token (the
// capability_api_token, deployment-owned — NOT any run's handle) and sends the
// run's opaque handle only in the request body, never in a header, log, or URL.
//
// The client is the sole authority the proxy trusts for run identity and budget:
// a model call is authorized only by a fresh Verify + Reserve against this API,
// never by caller-supplied fields.
type capClient struct {
	baseURL string
	token   string
	http    *http.Client
}

// newCapClient builds a capability client. baseURL and token must be non-empty;
// callers gate on capabilityEnabled() before constructing one.
func newCapClient(baseURL, token string, timeout time.Duration, transport http.RoundTripper) *capClient {
	client := &http.Client{Timeout: timeout}
	if transport != nil {
		client.Transport = transport
	}
	return &capClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    client,
	}
}

type capVerifyRequestBody struct {
	Handle string `json:"handle"`
}

type capVerifyResponseBody struct {
	AgentType      string   `json:"agent_type"`
	Mode           string   `json:"mode"`
	RunID          string   `json:"run_id"`
	WorkItemID     string   `json:"work_item_id"`
	AllowedModels  []string `json:"allowed_models"`
	CallBudget     int64    `json:"call_budget"`
	TokenBudget    int64    `json:"token_budget"`
	Expiry         string   `json:"expiry"`
	ReservedCalls  int64    `json:"reserved_calls"`
	ReservedTokens int64    `json:"reserved_tokens"`
}

type capReserveRequestBody struct {
	Handle string `json:"handle"`
	Model  string `json:"model,omitempty"`
	Calls  int64  `json:"calls"`
	Tokens int64  `json:"tokens"`
}

type capReserveResponseBody struct {
	ReservedCalls  int64 `json:"reserved_calls"`
	ReservedTokens int64 `json:"reserved_tokens"`
}

// verify authenticates the opaque handle against the broker and returns the
// trusted claims. It fails closed: a transport error or non-2xx status becomes
// errCapUnavailable (5xx / network) or errCapDenied (4xx), and the handle is
// never included in any returned error.
func (c *capClient) verify(ctx context.Context, handle string) (capClaims, error) {
	var out capVerifyResponseBody
	if err := c.post(ctx, "/v1/capabilities/verify", capVerifyRequestBody{Handle: handle}, &out); err != nil {
		return capClaims{}, err
	}
	expiry, err := time.Parse(time.RFC3339Nano, out.Expiry)
	if err != nil {
		return capClaims{}, fmt.Errorf("%w: unparseable expiry", errCapDenied)
	}
	return capClaims{
		AgentType:      out.AgentType,
		Mode:           out.Mode,
		RunID:          out.RunID,
		WorkItemID:     out.WorkItemID,
		AllowedModels:  out.AllowedModels,
		CallBudget:     out.CallBudget,
		TokenBudget:    out.TokenBudget,
		Expiry:         expiry.UTC(),
		ReservedCalls:  out.ReservedCalls,
		ReservedTokens: out.ReservedTokens,
	}, nil
}

// reserve atomically authorizes and records a call/token reservation for the
// handle's run against the broker. The broker performs the read-authorize-write
// in a single transaction, so concurrent reservations across proxy instances or
// goroutines cannot exceed the budget. It fails closed on any negative verdict.
func (c *capClient) reserve(ctx context.Context, handle, model string, calls, tokens int64) (capReserveResponseBody, error) {
	var out capReserveResponseBody
	err := c.post(ctx, "/v1/capabilities/reserve", capReserveRequestBody{
		Handle: handle, Model: model, Calls: calls, Tokens: tokens,
	}, &out)
	return out, err
}

// post sends one authenticated JSON request to the private capability API and
// decodes a JSON response into out. The static API token authenticates the proxy
// to the broker; the run handle travels only in body. Non-2xx responses map to
// errCapDenied (4xx) or errCapUnavailable (5xx / transport), and the response
// body — which may echo an error code but never the handle — is discarded.
func (c *capClient) post(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%w: encode request", errCapUnavailable)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("%w: build request", errCapUnavailable)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", errCapUnavailable, contextCause(ctx, err).Error())
	}
	defer closeBody(resp.Body)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, capMaxResponseBytes))
	if err != nil {
		return fmt.Errorf("%w: read response", errCapUnavailable)
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("%w: decode response", errCapDenied)
		}
		return nil
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: status %d", errCapUnavailable, resp.StatusCode)
	default:
		// 4xx: a definite negative verdict (unauthorized, not found, revoked,
		// expired, budget, model denial, invalid). Fail closed.
		return fmt.Errorf("%w: status %d", errCapDenied, resp.StatusCode)
	}
}

// contextCause prefers the context's cancellation cause (e.g. deadline) so an
// unavailable-API error is legible without leaking request detail.
func contextCause(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	return err
}
