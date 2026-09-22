// Package capability is an INERT Stage-4 foundation for broker-issued per-run
// capabilities.
//
// The authoritative design (agent-infra-docs/design/agent-platform-coupling.md,
// "Per-mode authority must be enforced at call time") COMMITS to broker-issued
// per-run capabilities as the mechanism: the execution class promises no
// standing credentials, so a capability binds immutable claims minted by the
// broker at launch and expiring with the run, and consumers must derive or
// validate those claims from the capability rather than trusting a request body
// or header — in particular the model proxy must stop accepting a
// caller-asserted run_id.
//
// This package ships the strongly-typed, immutable claims and the
// validation/authorization evaluator interfaces consumers will use instead of
// caller headers/body. It is deliberately NOT wired into any live path: no
// handler mints or verifies a capability, no config enables it, no launch or
// model-proxy consumer is changed, and no static per-mode principal is migrated.
//
// What the design does NOT decide, and this package therefore does NOT choose:
// the signing / token serialization / key-management mechanism by which a minted
// capability travels from the broker (issuer) to a consumer (verifier). Those
// two roles are represented here as explicit seams — the Issuer and Verifier
// interfaces — with NO implementation. Picking a concrete mechanism (a signed
// token format, a key hierarchy, rotation) is the remaining Stage-4 decision;
// see plans/agent-handoff.md. The Claims themselves, their validation, and the
// authorization evaluator do not depend on that choice, so they can land now.
package capability

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Mode is a capability's run mode. The design carries mode in the typed input,
// not a command line; a capability authorizes exactly one mode.
type Mode string

// Errors callers are expected to distinguish.
var (
	ErrInvalidClaims     = errors.New("capability claims are invalid")
	ErrExpired           = errors.New("capability has expired")
	ErrAgentTypeMismatch = errors.New("capability agent_type does not match the request")
	ErrModeMismatch      = errors.New("capability mode does not match the request")
	ErrRunMismatch       = errors.New("capability run_id does not match the request")
	ErrWorkItemMismatch  = errors.New("capability work_item_id does not match the request")
	ErrModelDenied       = errors.New("model is not in the capability's allowed_models")
	ErrCallBudget        = errors.New("capability call budget is exhausted")
	ErrTokenBudget       = errors.New("capability token budget is exhausted")
)

// Claims is the immutable set the design binds into a per-run capability:
//
//	agent_type, mode, run_id, allowed_models, call_budget, token_budget, expiry
//
// plus work_item_id, which the merged (inert) run-to-PR correlation outbox
// requires to bind a correlation to its originating WorkItem.
//
// Claims is a value type with only unexported fields, so a holder cannot mutate
// it after construction. Copies are independent (see Clone): the allowed-models
// set is copied in and out, never aliased.
type Claims struct {
	agentType     string
	mode          Mode
	runID         string
	workItemID    string
	allowedModels map[string]struct{}
	callBudget    int64
	tokenBudget   int64
	expiry        time.Time
}

// ClaimsInput is the mutable constructor input. NewClaims validates it and
// returns an immutable Claims; the input may be reused or mutated afterward
// without affecting the returned value.
type ClaimsInput struct {
	AgentType     string
	Mode          Mode
	RunID         string
	WorkItemID    string
	AllowedModels []string
	CallBudget    int64
	TokenBudget   int64
	Expiry        time.Time
}

// NewClaims validates the input and returns immutable Claims. Every field is
// required: the design's claims are all load-bearing, and an inert foundation
// must not model a partial capability. Budgets must be positive; expiry must be
// a non-zero instant; allowed_models must be non-empty with no blank entry.
func NewClaims(in ClaimsInput) (Claims, error) {
	if in.AgentType == "" {
		return Claims{}, fmt.Errorf("%w: agent_type is required", ErrInvalidClaims)
	}
	if in.Mode == "" {
		return Claims{}, fmt.Errorf("%w: mode is required", ErrInvalidClaims)
	}
	if in.RunID == "" {
		return Claims{}, fmt.Errorf("%w: run_id is required", ErrInvalidClaims)
	}
	if in.WorkItemID == "" {
		return Claims{}, fmt.Errorf("%w: work_item_id is required", ErrInvalidClaims)
	}
	if len(in.AllowedModels) == 0 {
		return Claims{}, fmt.Errorf("%w: allowed_models must be non-empty", ErrInvalidClaims)
	}
	if in.CallBudget <= 0 {
		return Claims{}, fmt.Errorf("%w: call_budget must be positive", ErrInvalidClaims)
	}
	if in.TokenBudget <= 0 {
		return Claims{}, fmt.Errorf("%w: token_budget must be positive", ErrInvalidClaims)
	}
	if in.Expiry.IsZero() {
		return Claims{}, fmt.Errorf("%w: expiry is required", ErrInvalidClaims)
	}
	models := make(map[string]struct{}, len(in.AllowedModels))
	for _, m := range in.AllowedModels {
		if m == "" {
			return Claims{}, fmt.Errorf("%w: allowed_models contains a blank entry", ErrInvalidClaims)
		}
		models[m] = struct{}{}
	}
	return Claims{
		agentType:     in.AgentType,
		mode:          in.Mode,
		runID:         in.RunID,
		workItemID:    in.WorkItemID,
		allowedModels: models,
		callBudget:    in.CallBudget,
		tokenBudget:   in.TokenBudget,
		expiry:        in.Expiry.UTC(),
	}, nil
}

// AgentType returns the agent type claim.
func (c Claims) AgentType() string { return c.agentType }

// Mode returns the mode claim.
func (c Claims) Mode() Mode { return c.mode }

// RunID returns the run id claim.
func (c Claims) RunID() string { return c.runID }

// WorkItemID returns the originating WorkItem id claim.
func (c Claims) WorkItemID() string { return c.workItemID }

// CallBudget returns the per-run call budget claim.
func (c Claims) CallBudget() int64 { return c.callBudget }

// TokenBudget returns the per-run token budget claim.
func (c Claims) TokenBudget() int64 { return c.tokenBudget }

// Expiry returns the capability expiry instant (UTC).
func (c Claims) Expiry() time.Time { return c.expiry }

// AllowedModels returns a sorted copy of the allowed-model set. The internal set
// is never aliased out, so a caller cannot widen a capability by mutating the
// returned slice.
func (c Claims) AllowedModels() []string {
	out := make([]string, 0, len(c.allowedModels))
	for m := range c.allowedModels {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// AllowsModel reports whether the model is in the allowed set.
func (c Claims) AllowsModel(model string) bool {
	_, ok := c.allowedModels[model]
	return ok
}

// Clone returns an independent copy. Because Claims exposes no setters and copies
// its map, this exists mainly to hand a value across a boundary while guaranteeing
// the recipient shares no mutable state.
func (c Claims) Clone() Claims {
	models := make(map[string]struct{}, len(c.allowedModels))
	for m := range c.allowedModels {
		models[m] = struct{}{}
	}
	c.allowedModels = models
	return c
}

// Request is what a consumer presents to be authorized against a capability. It
// names the run the consumer believes it is serving and, for model-proxy calls,
// the model and the increments it wants to reserve. A consumer builds this from
// the capability and its own call — never from caller-asserted headers/body.
type Request struct {
	AgentType      string
	Mode           Mode
	RunID          string
	WorkItemID     string
	Model          string // optional: only model-proxy calls set it
	Calls          int64  // calls to reserve this request (>=0)
	Tokens         int64  // tokens to reserve this request (>=0)
	ReservedCalls  int64  // calls already reserved for this run before this request
	ReservedTokens int64  // tokens already reserved for this run before this request
}

// Validator checks a capability's own well-formedness independent of any request
// — used by the offline validator and at verification time.
type Validator interface {
	Validate(claims Claims, now time.Time) error
}

// Authorizer decides whether a request is permitted by a capability. It performs
// no I/O and holds no state: identity, expiry, model, and budget are all decided
// from the claims and the request.
type Authorizer interface {
	Authorize(claims Claims, req Request, now time.Time) error
}

// Issuer is the broker-side seam that MINTS a capability for a run. Its concrete
// mechanism — how the minted capability is serialized and signed for transport —
// is the undecided Stage-4 decision and is intentionally unimplemented here.
type Issuer interface {
	// Issue mints a transportable capability carrying these claims. The return
	// type is intentionally opaque ([]byte) so this seam does not prejudge the
	// serialization/signing format.
	Issue(claims Claims) ([]byte, error)
}

// Verifier is the consumer-side seam that VERIFIES a transported capability back
// into trusted Claims, replacing caller-asserted ids. Its concrete mechanism is
// the same undecided decision as Issuer and is intentionally unimplemented here.
type Verifier interface {
	// Verify parses and authenticates a transported capability into Claims.
	Verify(token []byte) (Claims, error)
}

// PolicyEvaluator is the default, mechanism-independent implementation of
// Validator and Authorizer. It is safe to construct with a zero value.
type PolicyEvaluator struct{}

var (
	_ Validator  = PolicyEvaluator{}
	_ Authorizer = PolicyEvaluator{}
)

// Validate checks that the claims are still usable at now: well-formed (via the
// same invariants NewClaims enforces) and not expired.
func (PolicyEvaluator) Validate(claims Claims, now time.Time) error {
	if claims.agentType == "" || claims.mode == "" || claims.runID == "" ||
		claims.workItemID == "" || len(claims.allowedModels) == 0 ||
		claims.callBudget <= 0 || claims.tokenBudget <= 0 || claims.expiry.IsZero() {
		return ErrInvalidClaims
	}
	if !now.UTC().Before(claims.expiry) {
		return fmt.Errorf("%w: expired at %s", ErrExpired, claims.expiry.Format(time.RFC3339))
	}
	return nil
}

// Authorize permits req only when the capability is valid, unexpired, matches the
// request's identity on every claim, allows the model (when one is named), and
// has budget headroom for the requested increments.
func (e PolicyEvaluator) Authorize(claims Claims, req Request, now time.Time) error {
	if err := e.Validate(claims, now); err != nil {
		return err
	}
	if req.AgentType != claims.agentType {
		return ErrAgentTypeMismatch
	}
	if req.Mode != claims.mode {
		return ErrModeMismatch
	}
	if req.RunID != claims.runID {
		return ErrRunMismatch
	}
	if req.WorkItemID != claims.workItemID {
		return ErrWorkItemMismatch
	}
	if req.Model != "" && !claims.AllowsModel(req.Model) {
		return fmt.Errorf("%w: %q", ErrModelDenied, req.Model)
	}
	if req.Calls < 0 || req.Tokens < 0 || req.ReservedCalls < 0 || req.ReservedTokens < 0 {
		return fmt.Errorf("%w: negative reservation", ErrInvalidClaims)
	}
	if req.ReservedCalls+req.Calls > claims.callBudget {
		return fmt.Errorf("%w: %d of %d", ErrCallBudget, req.ReservedCalls+req.Calls, claims.callBudget)
	}
	if req.ReservedTokens+req.Tokens > claims.tokenBudget {
		return fmt.Errorf("%w: %d of %d", ErrTokenBudget, req.ReservedTokens+req.Tokens, claims.tokenBudget)
	}
	return nil
}
