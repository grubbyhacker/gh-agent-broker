package capability

import (
	"errors"
	"testing"
	"time"
)

func baseInput(expiry time.Time) ClaimsInput {
	return ClaimsInput{
		AgentType:     "coder",
		Mode:          "launch",
		RunID:         "run-1",
		WorkItemID:    "wi-1",
		AllowedModels: []string{"anthropic/claude", "openai/gpt"},
		CallBudget:    10,
		TokenBudget:   1000,
		Expiry:        expiry,
	}
}

func mustClaims(t *testing.T, in ClaimsInput) Claims {
	t.Helper()
	c, err := NewClaims(in)
	if err != nil {
		t.Fatalf("NewClaims: %v", err)
	}
	return c
}

func okRequest() Request {
	return Request{AgentType: "coder", Mode: "launch", RunID: "run-1", WorkItemID: "wi-1"}
}

func TestNewClaimsRejectsMissingIdentityOrExpiry(t *testing.T) {
	future := time.Now().Add(time.Hour)
	cases := map[string]func(*ClaimsInput){
		"no agent_type":   func(in *ClaimsInput) { in.AgentType = "" },
		"no mode":         func(in *ClaimsInput) { in.Mode = "" },
		"no run_id":       func(in *ClaimsInput) { in.RunID = "" },
		"no work_item_id": func(in *ClaimsInput) { in.WorkItemID = "" },
		"zero expiry":     func(in *ClaimsInput) { in.Expiry = time.Time{} },
		"blank model":     func(in *ClaimsInput) { in.AllowedModels = []string{""} },
		"negative call":   func(in *ClaimsInput) { in.CallBudget = -1 },
		"negative token":  func(in *ClaimsInput) { in.TokenBudget = -1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := baseInput(future)
			mutate(&in)
			if _, err := NewClaims(in); !errors.Is(err, ErrInvalidClaims) {
				t.Fatalf("expected ErrInvalidClaims, got %v", err)
			}
		})
	}
}

// modelDisabledInput is the deployed youknowme-curator reconcile shape:
// model.access=false → no allowed models, both budgets zero.
func modelDisabledInput(expiry time.Time) ClaimsInput {
	return ClaimsInput{
		AgentType:     "youknowme-curator",
		Mode:          "reconcile",
		RunID:         "run-1",
		WorkItemID:    "wi-1",
		AllowedModels: nil,
		CallBudget:    0,
		TokenBudget:   0,
		Expiry:        expiry,
	}
}

func TestModelDisabledClaimsAreValid(t *testing.T) {
	claims, err := NewClaims(modelDisabledInput(time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("model-disabled reconcile claims rejected: %v", err)
	}
	if claims.ModelEnabled() {
		t.Fatal("model-disabled claims report ModelEnabled=true")
	}
	if err := (PolicyEvaluator{}).Validate(claims, time.Now()); err != nil {
		t.Fatalf("Validate model-disabled: %v", err)
	}
}

func TestMixedModelStatesRejected(t *testing.T) {
	future := time.Now().Add(time.Hour)
	cases := map[string]ClaimsInput{
		"models without budget":         {AgentType: "a", Mode: "m", RunID: "r", WorkItemID: "w", AllowedModels: []string{"x"}, CallBudget: 0, TokenBudget: 0, Expiry: future},
		"budget without models":         {AgentType: "a", Mode: "m", RunID: "r", WorkItemID: "w", AllowedModels: nil, CallBudget: 5, TokenBudget: 5, Expiry: future},
		"call budget without models":    {AgentType: "a", Mode: "m", RunID: "r", WorkItemID: "w", AllowedModels: nil, CallBudget: 5, TokenBudget: 0, Expiry: future},
		"token budget without models":   {AgentType: "a", Mode: "m", RunID: "r", WorkItemID: "w", AllowedModels: nil, CallBudget: 0, TokenBudget: 5, Expiry: future},
		"models with call budget only":  {AgentType: "a", Mode: "m", RunID: "r", WorkItemID: "w", AllowedModels: []string{"x"}, CallBudget: 5, TokenBudget: 0, Expiry: future},
		"models with token budget only": {AgentType: "a", Mode: "m", RunID: "r", WorkItemID: "w", AllowedModels: []string{"x"}, CallBudget: 0, TokenBudget: 5, Expiry: future},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClaims(in); !errors.Is(err, ErrInvalidClaims) {
				t.Fatalf("expected ErrInvalidClaims for mixed state, got %v", err)
			}
		})
	}
}

func TestAuthorizeModelDisabledAllowsIdentityOnly(t *testing.T) {
	claims := mustClaims(t, modelDisabledInput(time.Now().Add(time.Hour)))
	e := PolicyEvaluator{}
	now := time.Now()

	// Identity-only operation with zero reservation is allowed.
	identityReq := Request{AgentType: "youknowme-curator", Mode: "reconcile", RunID: "run-1", WorkItemID: "wi-1"}
	if err := e.Authorize(claims, identityReq, now); err != nil {
		t.Fatalf("identity-only op on model-disabled claims denied: %v", err)
	}

	// Any model request is denied.
	modelReq := identityReq
	modelReq.Model = "anything"
	if err := e.Authorize(claims, modelReq, now); !errors.Is(err, ErrModelDenied) {
		t.Fatalf("model request on model-disabled = %v, want ErrModelDenied", err)
	}
	// Any call reservation is denied.
	callReq := identityReq
	callReq.Calls = 1
	if err := e.Authorize(claims, callReq, now); !errors.Is(err, ErrCallBudget) {
		t.Fatalf("call request on model-disabled = %v, want ErrCallBudget", err)
	}
	// Any token reservation is denied.
	tokenReq := identityReq
	tokenReq.Tokens = 1
	if err := e.Authorize(claims, tokenReq, now); !errors.Is(err, ErrTokenBudget) {
		t.Fatalf("token request on model-disabled = %v, want ErrTokenBudget", err)
	}
}

func TestAuthorizeHappyPath(t *testing.T) {
	claims := mustClaims(t, baseInput(time.Now().Add(time.Hour)))
	req := okRequest()
	req.Model = "openai/gpt"
	req.Calls = 1
	req.Tokens = 100
	if err := (PolicyEvaluator{}).Authorize(claims, req, time.Now()); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	claims := mustClaims(t, baseInput(now.Add(time.Minute)))
	e := PolicyEvaluator{}
	if err := e.Authorize(claims, okRequest(), now); err != nil {
		t.Fatalf("unexpired Authorize: %v", err)
	}
	if err := e.Authorize(claims, okRequest(), now.Add(2*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	// A capability at or past its expiry instant is expired.
	if err := e.Validate(claims, now.Add(time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expiry at instant to be expired, got %v", err)
	}
}

func TestIdentityMismatches(t *testing.T) {
	claims := mustClaims(t, baseInput(time.Now().Add(time.Hour)))
	e := PolicyEvaluator{}
	now := time.Now()
	cases := []struct {
		name string
		req  Request
		want error
	}{
		{"agent_type", Request{AgentType: "other", Mode: "launch", RunID: "run-1", WorkItemID: "wi-1"}, ErrAgentTypeMismatch},
		{"mode", Request{AgentType: "coder", Mode: "dry_run", RunID: "run-1", WorkItemID: "wi-1"}, ErrModeMismatch},
		{"run_id", Request{AgentType: "coder", Mode: "launch", RunID: "run-2", WorkItemID: "wi-1"}, ErrRunMismatch},
		{"work_item_id", Request{AgentType: "coder", Mode: "launch", RunID: "run-1", WorkItemID: "wi-2"}, ErrWorkItemMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := e.Authorize(claims, tc.req, now); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestModelDenial(t *testing.T) {
	claims := mustClaims(t, baseInput(time.Now().Add(time.Hour)))
	req := okRequest()
	req.Model = "unlisted/model"
	if err := (PolicyEvaluator{}).Authorize(claims, req, time.Now()); !errors.Is(err, ErrModelDenied) {
		t.Fatalf("expected ErrModelDenied, got %v", err)
	}
}

func TestCallBudgetBounds(t *testing.T) {
	claims := mustClaims(t, baseInput(time.Now().Add(time.Hour))) // call_budget=10
	e := PolicyEvaluator{}
	now := time.Now()

	req := okRequest()
	req.ReservedCalls = 9
	req.Calls = 1
	if err := e.Authorize(claims, req, now); err != nil {
		t.Fatalf("at-budget should pass: %v", err)
	}
	req.Calls = 2 // 9+2=11 > 10
	if err := e.Authorize(claims, req, now); !errors.Is(err, ErrCallBudget) {
		t.Fatalf("expected ErrCallBudget, got %v", err)
	}
}

func TestTokenBudgetBounds(t *testing.T) {
	claims := mustClaims(t, baseInput(time.Now().Add(time.Hour))) // token_budget=1000
	e := PolicyEvaluator{}
	now := time.Now()

	req := okRequest()
	req.ReservedTokens = 900
	req.Tokens = 100
	if err := e.Authorize(claims, req, now); err != nil {
		t.Fatalf("at-budget should pass: %v", err)
	}
	req.Tokens = 101 // 900+101=1001 > 1000
	if err := e.Authorize(claims, req, now); !errors.Is(err, ErrTokenBudget) {
		t.Fatalf("expected ErrTokenBudget, got %v", err)
	}
}

func TestImmutabilityAllowedModelsCopyIn(t *testing.T) {
	in := baseInput(time.Now().Add(time.Hour))
	models := []string{"anthropic/claude"}
	in.AllowedModels = models
	claims := mustClaims(t, in)

	// Mutating the caller's input slice must not widen the capability.
	models[0] = "attacker/model"
	if claims.AllowsModel("attacker/model") {
		t.Fatal("mutating input slice widened the capability")
	}
	if !claims.AllowsModel("anthropic/claude") {
		t.Fatal("original model was lost")
	}
}

func TestImmutabilityAllowedModelsCopyOut(t *testing.T) {
	claims := mustClaims(t, baseInput(time.Now().Add(time.Hour)))
	got := claims.AllowedModels()
	for i := range got {
		got[i] = "mutated"
	}
	// Mutating the returned slice must not affect the capability.
	if claims.AllowsModel("mutated") {
		t.Fatal("mutating returned slice widened the capability")
	}
	if !claims.AllowsModel("openai/gpt") {
		t.Fatal("capability lost a model after caller mutated the returned slice")
	}
}

func TestCloneIsIndependent(t *testing.T) {
	claims := mustClaims(t, baseInput(time.Now().Add(time.Hour)))
	clone := claims.Clone()
	// The clone exposes the same values...
	if clone.AgentType() != claims.AgentType() || clone.RunID() != claims.RunID() {
		t.Fatal("clone lost claim values")
	}
	// ...and mutating a slice obtained from one does not affect the other.
	m := clone.AllowedModels()
	for i := range m {
		m[i] = "x"
	}
	if !claims.AllowsModel("openai/gpt") || !clone.AllowsModel("openai/gpt") {
		t.Fatal("clone and original share mutable model state")
	}
}

func TestNegativeReservationRejected(t *testing.T) {
	claims := mustClaims(t, baseInput(time.Now().Add(time.Hour)))
	req := okRequest()
	req.Calls = -1
	if err := (PolicyEvaluator{}).Authorize(claims, req, time.Now()); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("expected ErrInvalidClaims for negative reservation, got %v", err)
	}
}
