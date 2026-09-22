package sandbox

import (
	"context"
	"fmt"
	"strings"

	"gh-agent-broker/internal/capability"
)

// capabilityEnvKey is the single controlled-transport env var the plaintext
// per-run capability handle is injected under. It reaches ONLY the launched
// run's container environment (see runtimeSpec). The handle is never written to
// RunMetadata, the audit log, run status, or disk: only its SHA-256 lives in the
// capability store.
const capabilityEnvKey = "AGENT_CAPABILITY_TOKEN"

// CapabilityMinter is the launch-path view of the broker's capability store. The
// broker is the sole mint authority: Issue returns the plaintext handle exactly
// once and persists only its digest; Revoke fails a handle closed when a launch
// does not reach a running state.
type CapabilityMinter interface {
	Issue(ctx context.Context, claims capability.Claims) (string, error)
	Revoke(ctx context.Context, handle string) error
}

// SetCapabilityMinter wires the broker's capability store into the launch path.
// When set, an AgentType-backed launch mints one opaque per-run capability whose
// claims are derived only from the template's deployment-owned capability policy
// and the broker-generated run identity, and injects the plaintext handle into
// the launched run's controlled transport. It is optional: a broker configured
// without a capability store launches non-AgentType templates unchanged.
func (s *Service) SetCapabilityMinter(minter CapabilityMinter) {
	s.capabilities = minter
}

// mintsCapability reports whether a launch of tmpl must mint a per-run
// capability. Only AgentType-backed templates do; that is the sole launch shape
// the design scopes, and validateTemplate guarantees such a template carries a
// capability policy and that capability_store_path is configured.
func mintsCapability(tmpl Template) bool {
	return tmpl.AgentType != "" && tmpl.Capability != nil
}

// deriveCapabilityClaims builds the immutable per-run capability claims strictly
// from deployment-owned policy (tmpl.AgentType and tmpl.Capability) and the
// broker-frozen run/work identity carried on meta. It NEVER reads caller-supplied
// launch input, parameters, or any caller-asserted run_id/claims.
//
//   - agent_type        <- tmpl.AgentType (deployment-owned)
//   - mode              <- tmpl.Capability.Mode (deployment-owned)
//   - allowed_models    <- tmpl.Capability.AllowedModels (deployment-owned)
//   - call/token budget <- tmpl.Capability.CallBudget/TokenBudget (deployment-owned)
//   - run_id            <- meta.RunID (broker-generated newRunID)
//   - work_item_id      <- meta.WorkItemID (authoritative Signal Plane WorkItem
//     identity, frozen at the authenticated control-plane launch boundary). It is
//     a DISTINCT durable identity and is never equated with run_id.
//   - expiry            <- meta.Deadline (broker-computed now+runtimeLimit)
//
// It fails closed when the authoritative WorkItemID is absent or was set equal to
// the run id: an opt-in capability launch requires the WorkItem launcher to have
// supplied a real, distinct WorkItem identity.
//
// The model-disabled state (ModelAccess=false: empty models, zero budgets) is
// preserved: NewClaims accepts it as identity-only and rejects any mixed state.
func deriveCapabilityClaims(tmpl Template, meta RunMetadata) (capability.Claims, error) {
	if tmpl.AgentType == "" {
		return capability.Claims{}, fmt.Errorf("capability derivation requires an agent_type-backed template")
	}
	if tmpl.Capability == nil {
		return capability.Claims{}, fmt.Errorf("capability derivation failed: template %q declares agent_type %q but no capability policy", meta.Template, tmpl.AgentType)
	}
	if meta.RunID == "" {
		return capability.Claims{}, fmt.Errorf("capability derivation requires a broker-generated run_id")
	}
	if strings.TrimSpace(meta.WorkItemID) == "" {
		return capability.Claims{}, fmt.Errorf("capability derivation requires an authoritative work_item_id; the WorkItem launcher supplied none")
	}
	if meta.WorkItemID == meta.RunID {
		return capability.Claims{}, fmt.Errorf("capability derivation refuses a work_item_id equal to run_id; WorkItem identity is a distinct Signal Plane identity")
	}
	if meta.Deadline.IsZero() {
		return capability.Claims{}, fmt.Errorf("capability derivation requires a broker-computed deadline for expiry")
	}
	pol := tmpl.Capability
	var models []string
	if pol.ModelAccess {
		models = append(models, pol.AllowedModels...)
	}
	return capability.NewClaims(capability.ClaimsInput{
		AgentType:     tmpl.AgentType,
		Mode:          capability.Mode(pol.Mode),
		RunID:         meta.RunID,
		WorkItemID:    meta.WorkItemID,
		AllowedModels: models,
		CallBudget:    pol.CallBudget,
		TokenBudget:   pol.TokenBudget,
		Expiry:        meta.Deadline,
	})
}

// mintLaunchCapability derives claims and mints one opaque per-run capability
// for an AgentType-backed launch, returning the plaintext handle. It fails
// CLOSED: if the template needs a capability but no store is configured, or the
// claims cannot be derived, the launch is refused rather than started without a
// capability. Templates that do not mint a capability return an empty handle and
// no error.
func (s *Service) mintLaunchCapability(ctx context.Context, tmpl Template, meta RunMetadata) (string, error) {
	if !mintsCapability(tmpl) {
		return "", nil
	}
	if s.capabilities == nil {
		return "", fmt.Errorf("policy denial: template %q declares agent_type %q but the broker has no capability store configured; launch refused", meta.Template, tmpl.AgentType)
	}
	claims, err := deriveCapabilityClaims(tmpl, meta)
	if err != nil {
		return "", fmt.Errorf("policy denial: %w; launch refused", err)
	}
	handle, err := s.capabilities.Issue(ctx, claims)
	if err != nil {
		return "", fmt.Errorf("mint per-run capability: %w", err)
	}
	return handle, nil
}

// revokeLaunchCapability fails a minted handle closed when a launch does not
// reach a running state (container create/start failure or a terminal launch
// error). It is best-effort and idempotent on the store side; a revoke failure
// must not mask the original launch error, so callers ignore its result beyond
// logging. An empty handle (no capability minted) is a no-op.
func (s *Service) revokeLaunchCapability(ctx context.Context, handle string) {
	if handle == "" || s.capabilities == nil {
		return
	}
	if err := s.capabilities.Revoke(ctx, handle); err != nil {
		// The handle plaintext is never logged; report the revoke failure only.
		s.logCapabilityRevokeFailure(err)
	}
}
