package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gh-agent-broker/internal/capability"
)

// spyMinter records Issue/Revoke calls so a test can assert the launch path
// mints and revokes without a real store. It returns a fixed sentinel handle.
type spyMinter struct {
	handle    string
	issueErr  error
	revokeErr error
	issued    []capability.Claims
	revoked   []string
}

func (m *spyMinter) Issue(_ context.Context, claims capability.Claims) (string, error) {
	if m.issueErr != nil {
		return "", m.issueErr
	}
	m.issued = append(m.issued, claims)
	if m.handle == "" {
		m.handle = strings.Repeat("a", 64)
	}
	return m.handle, nil
}

func (m *spyMinter) Revoke(_ context.Context, handle string) error {
	m.revoked = append(m.revoked, handle)
	return m.revokeErr
}

func agentTypeLaunchService(t *testing.T, mutate func(*CapabilityPolicy)) (*Service, *fakeRuntime, Config) {
	t.Helper()
	cfg := releaseTestConfig(t, "coder")
	if mutate != nil {
		tmpl := cfg.Templates["worker"]
		pol := *tmpl.Capability
		mutate(&pol)
		tmpl.Capability = &pol
		cfg.Templates["worker"] = tmpl
	}
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, testAudit(t))
	service.SetReleaseResolver(&fakeResolver{release: ResolvedRelease{Generation: 5, ImageReference: testResolvedRef, ImageDigest: testResolvedDigest}})
	return service, runtime, cfg
}

// The claims a launch mints are derived only from deployment-owned policy and
// the broker-generated run identity. Caller-supplied run_id/claims are refused
// at the input boundary (LaunchAgentInput rejects unknown fields), so the derived
// claims can only reflect the template policy and the run the broker created.
func TestLaunchDerivesImmutableCapabilityClaims(t *testing.T) {
	service, runtime, _ := agentTypeLaunchService(t, nil)
	minter := &spyMinter{}
	service.SetCapabilityMinter(minter)

	out := launchWorker(context.Background(), t, service)

	if len(minter.issued) != 1 {
		t.Fatalf("Issue called %d times, want exactly one mint per launch", len(minter.issued))
	}
	claims := minter.issued[0]
	if claims.AgentType() != "coder" {
		t.Fatalf("agent_type = %q, want the template's deployment-owned agent_type", claims.AgentType())
	}
	if claims.Mode() != "implement" {
		t.Fatalf("mode = %q, want the policy mode", claims.Mode())
	}
	// run_id and work_item_id are the broker-generated run identity, not caller input.
	if claims.RunID() != out.RunID || claims.WorkItemID() != out.RunID {
		t.Fatalf("run_id=%q work_item_id=%q, want the broker run id %q", claims.RunID(), claims.WorkItemID(), out.RunID)
	}
	if got := claims.AllowedModels(); len(got) != 1 || got[0] != "gpt-5.6-terra" {
		t.Fatalf("allowed_models = %v, want the policy models", got)
	}
	if claims.CallBudget() != 64 || claims.TokenBudget() != 200000 {
		t.Fatalf("budgets = call %d token %d, want the policy budgets", claims.CallBudget(), claims.TokenBudget())
	}
	// The plaintext handle went into the container transport, not the run record.
	spec := runtime.lastSpec()
	if spec.Env[capabilityEnvKey] != minter.handle {
		t.Fatalf("capability handle env = %q, want the minted handle", spec.Env[capabilityEnvKey])
	}
}

// Expiry is the broker-computed deadline (now + runtime limit), not a
// caller-controlled or policy-static value.
func TestLaunchCapabilityExpiryIsRunDeadline(t *testing.T) {
	service, _, _ := agentTypeLaunchService(t, nil)
	minter := &spyMinter{}
	service.SetCapabilityMinter(minter)

	out := launchWorker(context.Background(), t, service)
	meta := lookupTestRun(t, service, out.RunID)

	if len(minter.issued) != 1 {
		t.Fatalf("Issue called %d times", len(minter.issued))
	}
	if !minter.issued[0].Expiry().Equal(meta.Deadline.UTC()) {
		t.Fatalf("capability expiry = %s, want run deadline %s", minter.issued[0].Expiry(), meta.Deadline.UTC())
	}
}

// A model-disabled policy (model_access=false: empty models + zero budgets) mints
// an identity-only capability, and the handle is still injected into transport.
func TestLaunchModelDisabledCapabilityIsPreserved(t *testing.T) {
	service, runtime, _ := agentTypeLaunchService(t, func(p *CapabilityPolicy) {
		p.ModelAccess = false
		p.AllowedModels = nil
		p.CallBudget = 0
		p.TokenBudget = 0
	})
	minter := &spyMinter{}
	service.SetCapabilityMinter(minter)

	launchWorker(context.Background(), t, service)

	if len(minter.issued) != 1 {
		t.Fatalf("Issue called %d times", len(minter.issued))
	}
	claims := minter.issued[0]
	if claims.ModelEnabled() {
		t.Fatal("model-disabled policy minted a model-enabled capability")
	}
	if len(claims.AllowedModels()) != 0 || claims.CallBudget() != 0 || claims.TokenBudget() != 0 {
		t.Fatalf("model-disabled capability not preserved: models=%v call=%d token=%d",
			claims.AllowedModels(), claims.CallBudget(), claims.TokenBudget())
	}
	if runtime.lastSpec().Env[capabilityEnvKey] != minter.handle {
		t.Fatal("model-disabled capability handle not injected into transport")
	}
}

// The plaintext handle must reach ONLY the container env: never the run metadata
// on disk, the run status, or the audit log. Only the store holds its SHA-256.
func TestLaunchCapabilityHandleIsNotPersistedOrLogged(t *testing.T) {
	// Use a real store so the whole mint path runs; read the handle from the
	// injected env, then prove that exact string appears nowhere durable.
	service, runtime, cfg := agentTypeLaunchService(t, nil)
	newTestCapabilityStore(t, service)

	out := launchWorker(context.Background(), t, service)
	handle := runtime.lastSpec().Env[capabilityEnvKey]
	if len(handle) != 64 {
		t.Fatalf("expected a 64-hex minted handle in transport, got %q", handle)
	}

	// Run metadata on disk must not contain the plaintext handle.
	//nolint:gosec // G304: test reads generated metadata under this test's temp run dir.
	metaBytes, err := os.ReadFile(filepath.Join(cfg.RunsDir, out.RunID, "metadata.json"))
	if err != nil {
		t.Fatalf("read metadata.json: %v", err)
	}
	if strings.Contains(string(metaBytes), handle) {
		t.Fatal("plaintext capability handle leaked into run metadata.json")
	}

	// Audit log must not contain the plaintext handle.
	if data, err := os.ReadFile(cfg.Audit.Path); err == nil { //nolint:gosec // G304: test's own temp audit path.
		if strings.Contains(string(data), handle) {
			t.Fatal("plaintext capability handle leaked into the audit log")
		}
	}

	// The run status projection must not carry the handle either.
	meta := lookupTestRun(t, service, out.RunID)
	if strings.Contains(meta.Error, handle) || strings.Contains(meta.Task, handle) {
		t.Fatal("plaintext capability handle leaked into run metadata fields")
	}
}

// An AgentType-backed launch fails CLOSED when no capability minter is wired: the
// launch is refused and no container is created.
func TestLaunchFailsClosedWithoutCapabilityStore(t *testing.T) {
	service, runtime, _ := agentTypeLaunchService(t, nil)
	// Deliberately do NOT wire a minter.

	_, err := service.LaunchAgent(context.Background(), LaunchAgentInput{
		Template: "worker", Task: "make the change", Repo: "owner/repo", BaseBranch: "main",
	})
	if err == nil || !strings.Contains(err.Error(), "no capability store configured") {
		t.Fatalf("LaunchAgent() error = %v, want fail-closed refusal for missing capability store", err)
	}
	if spec := runtime.lastSpec(); spec.RunID != "" {
		t.Fatalf("a refused launch created container %q; it must not create one", spec.RunID)
	}
}

// When container creation fails after a capability was minted, the capability is
// revoked so a leaked handle cannot be used by anything that observed it.
func TestLaunchRevokesCapabilityOnCreateFailure(t *testing.T) {
	service, runtime, _ := agentTypeLaunchService(t, nil)
	minter := &spyMinter{}
	service.SetCapabilityMinter(minter)
	runtime.createErr = errors.New("docker create failed")

	_, err := service.LaunchAgent(context.Background(), LaunchAgentInput{
		Template: "worker", Task: "make the change", Repo: "owner/repo", BaseBranch: "main",
	})
	if err == nil {
		t.Fatal("LaunchAgent() succeeded despite a create failure")
	}
	if len(minter.issued) != 1 {
		t.Fatalf("Issue called %d times, want one mint before the create attempt", len(minter.issued))
	}
	if len(minter.revoked) != 1 || minter.revoked[0] != minter.handle {
		t.Fatalf("Revoke calls = %v, want the minted handle revoked exactly once", minter.revoked)
	}
}

// A non-AgentType template mints no capability and injects no handle: the feature
// is scoped to AgentType-backed launches and leaves the default path unchanged.
func TestLaunchWithoutAgentTypeMintsNoCapability(t *testing.T) {
	cfg := baseTestConfig(t)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, testAudit(t))
	minter := &spyMinter{}
	service.SetCapabilityMinter(minter)

	launchWorker(context.Background(), t, service)

	if len(minter.issued) != 0 {
		t.Fatalf("Issue called %d times for a non-AgentType template, want zero", len(minter.issued))
	}
	if _, ok := runtime.lastSpec().Env[capabilityEnvKey]; ok {
		t.Fatal("a non-AgentType launch injected a capability handle")
	}
}

// deriveCapabilityClaims reads only deployment-owned policy and the broker run
// identity; it never consults caller input. This exercises the derivation
// directly for the identity/expiry binding.
func TestDeriveCapabilityClaimsBindsRunIdentity(t *testing.T) {
	tmpl := Template{
		AgentType: "coder",
		Capability: &CapabilityPolicy{
			Mode: "implement", ModelAccess: true,
			AllowedModels: []string{"gpt-5.6-terra"}, CallBudget: 10, TokenBudget: 1000,
		},
	}
	deadline := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	meta := RunMetadata{RunID: "run-xyz", Template: "worker", Deadline: deadline}

	claims, err := deriveCapabilityClaims(tmpl, meta)
	if err != nil {
		t.Fatalf("deriveCapabilityClaims: %v", err)
	}
	if claims.RunID() != "run-xyz" || claims.WorkItemID() != "run-xyz" {
		t.Fatalf("run identity not bound: run_id=%q work_item_id=%q", claims.RunID(), claims.WorkItemID())
	}
	if !claims.Expiry().Equal(deadline) {
		t.Fatalf("expiry = %s, want deadline %s", claims.Expiry(), deadline)
	}

	// Missing broker run id / deadline fail closed.
	if _, err := deriveCapabilityClaims(tmpl, RunMetadata{Deadline: deadline}); err == nil {
		t.Fatal("derivation accepted an empty run_id")
	}
	if _, err := deriveCapabilityClaims(tmpl, RunMetadata{RunID: "run-xyz"}); err == nil {
		t.Fatal("derivation accepted a zero deadline")
	}
}
