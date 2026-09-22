package proxy

import (
	"context"
	"errors"
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

// reserveCapabilityCall atomically reserves exactly one call (and enforces the
// model) against the run's capability BEFORE the upstream request is forwarded.
// The broker performs the model check and the read-authorize-write in one
// transaction, so this is the single point that both enforces the allowed model
// under the verified policy and prevents concurrent calls from exceeding the
// call budget. Fail closed on any error.
func (s *Service) reserveCapabilityCall(ctx context.Context, res capAuthResult, model string) error {
	// A model-disabled capability may not make any model call. Deny locally
	// before contacting the API so the audit records model_denied, and so a
	// blank/mismatched model never reaches the reserve transaction.
	if !res.claims.modelEnabled() {
		return errCapDenied
	}
	if model == "" || !res.claims.allowsModel(model) {
		return errCapDenied
	}
	if _, err := s.caps.reserve(ctx, res.handle, model, 1, 0); err != nil {
		return err
	}
	return nil
}

// reserveCapabilityTokens records post-response token usage against the run's
// capability. It reserves zero calls (the call was already reserved) and the
// observed token total. A non-nil error means the run exceeded its token budget;
// the caller denies the response. Zero or negative usage is a no-op success.
func (s *Service) reserveCapabilityTokens(ctx context.Context, res capAuthResult, tokens int) error {
	if tokens <= 0 {
		return nil
	}
	if _, err := s.caps.reserve(ctx, res.handle, "", 0, int64(tokens)); err != nil {
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
