package proxy

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strings"
)

// capAuthResult carries the outcome of authenticating one request against the
// capability API: the trusted claims on success, or a category + HTTP status on
// failure. The plaintext handle is never stored here.
type capAuthResult struct {
	claims capClaims
	handle string
}

// bearerHandle extracts the opaque capability handle a run presents as its
// Bearer credential. The handle is the run's sole proof of identity to the
// proxy; it is returned to the caller of authenticateCapability only to be
// passed straight back to verify/reserve, and is never logged or audited.
func bearerHandle(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(auth, prefix))
}

// authenticateCapability verifies the run's handle and reconciles it with any
// legacy caller-supplied identity. It performs NO reservation — call
// reserveCapabilityCall next, before forwarding. callerRunID is the
// caller-asserted run id (body run_id or X-GH-Agent-Run-ID header), used only to
// REJECT a mismatch: the proxy derives the real run_id from the verified claims
// and never trusts the caller's value.
//
// Fail closed: a missing handle, an unreachable API, or any negative verdict
// returns an error and the request must be denied.
func (s *Service) authenticateCapability(ctx context.Context, r *http.Request, callerRunID string) (capAuthResult, error) {
	handle := bearerHandle(r)
	if handle == "" {
		return capAuthResult{}, errCapMissing
	}
	claims, err := s.caps.verify(ctx, handle)
	if err != nil {
		return capAuthResult{}, err
	}
	// Stop trusting caller identity: if a legacy run_id field is present and
	// disagrees with the verified claim, reject rather than override silently.
	if callerRunID != "" && callerRunID != claims.RunID {
		return capAuthResult{}, errCapIdentityMismatch
	}
	return capAuthResult{claims: claims, handle: handle}, nil
}

// preflightTokenBound returns a conservative upper bound for one upstream call:
// serialized request bytes plus the caller-declared maximum output tokens. A
// model token cannot encode less than one UTF-8 byte, so request bytes safely
// bound input tokens without depending on an upstream tokenizer. Capability-
// enforced calls must declare a positive output cap; otherwise forwarding would
// authorize unbounded model work. Overflow fails closed.
func preflightTokenBound(requestBytes, maxOutputTokens int) (int64, bool) {
	if requestBytes <= 0 || maxOutputTokens <= 0 {
		return 0, false
	}
	requestBound := int64(requestBytes)
	outputBound := int64(maxOutputTokens)
	if requestBound > math.MaxInt64-outputBound {
		return 0, false
	}
	return requestBound + outputBound, true
}

// reserveCapabilityBudget atomically reserves exactly one call and the complete
// conservative token bound while enforcing the model BEFORE forwarding. The
// broker performs model authorization and read-authorize-write in one
// transaction, preventing concurrent calls or streams from exceeding either
// budget. There is deliberately no post-response authorization: once an
// upstream call starts (especially an SSE stream), its cost is already incurred.
func (s *Service) reserveCapabilityBudget(ctx context.Context, res capAuthResult, model string, tokens int64) error {
	if !res.claims.modelEnabled() || tokens <= 0 {
		return errCapDenied
	}
	if model == "" || !res.claims.allowsModel(model) {
		return errCapDenied
	}
	if _, err := s.caps.reserve(ctx, res.handle, model, 1, tokens); err != nil {
		return err
	}
	return nil
}

// capStatus maps a capability enforcement error to an HTTP status and a stable,
// non-leaking error code. It never surfaces the handle or internal API detail.
func capStatus(err error) (int, string) {
	switch {
	case errors.Is(err, errCapMissing):
		return http.StatusUnauthorized, "capability_required"
	case errors.Is(err, errCapIdentityMismatch):
		return http.StatusForbidden, "run_id_mismatch"
	case errors.Is(err, errCapUnavailable):
		// Fail closed on an unreachable authority, but signal it is a
		// dependency failure rather than a client error.
		return http.StatusServiceUnavailable, "capability_unavailable"
	case errors.Is(err, errCapDenied):
		return http.StatusForbidden, "capability_denied"
	default:
		return http.StatusForbidden, "capability_denied"
	}
}

// capAuditError returns a bounded, handle-free string for the audit log.
func capAuditError(err error) string {
	_, code := capStatus(err)
	return code
}
