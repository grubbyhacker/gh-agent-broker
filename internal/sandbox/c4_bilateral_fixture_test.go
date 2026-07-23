package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	c4BilateralRepository              = "grubbyhacker/repository-worker-lifecycle-test"
	c4BilateralProfile                 = "general-writer-v1"
	c4BilateralAuthorityPrincipal      = "authority-worker-operator"
	c4BilateralPolicyAgent             = "fleiglabs-repo-agent"
	c4BilateralSessionID               = "agentd-c4-bilateral-session"
	c4BilateralFixtureControlSecretEnv = "C4_BILATERAL_BROKER_CONTROL_SECRET"
)

// c4BilateralAuthorityFixture is test-only input for the real child -> real
// broker Docker seam. The principal that owns the lease deliberately differs
// from the configured Git/App policy agent; profileAgentID is their only
// allowed bridge. Do not replace this with direct SQLite inserts.
type c4BilateralAuthorityFixture struct {
	AuthorityStorePath string
	WorkspaceRoot      string
	ProfileAgentID     string
	AgentID            string
	AgentSecret        string
	SessionID          string
	Lease              AuthorityLease
}

func newC4BilateralAuthorityFixture(t *testing.T, root string) c4BilateralAuthorityFixture {
	t.Helper()
	ctx := context.Background()
	if !filepath.IsAbs(root) {
		t.Fatal("C4 authority fixture root must be absolute")
	}
	controlSecret := strings.Repeat("a", 64)
	t.Setenv(c4BilateralFixtureControlSecretEnv, controlSecret)

	cfg := authorityTestConfig(t)
	cfg.AuthorityStore = filepath.Join(root, "authority-workers.sqlite")
	profile := cfg.AuthorityProfiles["writer"]
	profile.BrokerAgentID = c4BilateralPolicyAgent
	profile.BrokerSecretEnv = c4BilateralFixtureControlSecretEnv
	profile.Repositories = []string{c4BilateralRepository}
	profile.Operations = []string{"git.upload-pack", "git.receive-pack"}
	profile.BranchPolicy = BranchPolicy{AllowedPatterns: []string{`^agent/fleiglabs-repo-agent/[a-z0-9][a-z0-9-]{0,62}$`}, BaseBranches: []string{"main"}, GeneratePrefix: "agent/fleiglabs-repo-agent"}
	profile.SessionIsolation.WorkspaceRoot = filepath.Join(root, "workspaces")
	profile.SessionIsolation.UIDStart, profile.SessionIsolation.GIDStart = os.Getuid(), os.Getgid()
	cfg.AuthorityProfiles = map[string]AuthorityProfile{c4BilateralProfile: profile}
	cfg.AuthorityPrincipals = map[string]AuthorityPrincipal{
		c4BilateralAuthorityPrincipal: {Token: "c4-bilateral-authority-operator", AllowedProfiles: []string{c4BilateralProfile}, AllowedActions: []string{"provision", "health", "acquire"}},
	}
	cfg.RegisteredCoordinatorPrincipal = c4BilateralAuthorityPrincipal

	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	registerAuthorityTestIssuance(t, cfg.AuthorityStore, map[string]int64{c4BilateralProfile: 1})
	service := NewAuthorityWorkerService(cfg, store, &fakeAuthorityRuntime{}, nil, allowTestAuthorityIssuance{})
	service.newID = func() (string, error) { return "c4-bilateral-worker", nil }
	worker, err := service.Provision(ctx, c4BilateralAuthorityPrincipal, c4BilateralProfile)
	if err != nil {
		t.Fatalf("provision C4 authority worker: %v", err)
	}
	if _, err = service.SetHealth(ctx, c4BilateralAuthorityPrincipal, worker.WorkerID, "c4-fixture-ready", true); err != nil {
		t.Fatalf("ready C4 authority worker: %v", err)
	}

	request := registeredRequest(t, "c4-bilateral-work", "c4-bilateral-route")
	request.Profile = c4BilateralProfile
	request.Task.Parameters.Repository = c4BilateralRepository
	validated, err := validateRegisteredAdmission(request)
	if err != nil {
		t.Fatalf("validate C4 registered admission: %v", err)
	}
	request.AdmissionTaskDigest = validated.Digest
	admission, err := service.AcquireRegisteredSession(ctx, c4BilateralAuthorityPrincipal, request)
	if err != nil {
		t.Fatalf("acquire C4 registered authority lease: %v", err)
	}
	if err = store.BindAgentdSession(ctx, request.SessionBinding, c4BilateralSessionID); err != nil {
		t.Fatalf("bind C4 agentd session: %v", err)
	}
	effectID := "model:c4-bilateral-effect"
	if err = store.RecordRegisteredTurn(ctx, c4BilateralAuthorityPrincipal, request.SessionBinding, request.IdempotencyKey, registeredTurnState{SessionID: c4BilateralSessionID, TurnID: "turn:c4-bilateral", ModelEffectID: effectID, SubmitCursor: 1}); err != nil {
		t.Fatalf("record C4 registered turn: %v", err)
	}
	if err = store.RecordRegisteredEvents(ctx, c4BilateralAuthorityPrincipal, request.SessionBinding, 0, 1, []registeredEventProjection{{
		Cursor: 1, SessionID: c4BilateralSessionID, TurnID: "turn:c4-bilateral", ModelEffectID: effectID, Phase: "authorized",
		WorkerID: admission.Lease.WorkerID, StorageLineageID: admission.Lease.WorkerStorageLineageID, FenceEpoch: admission.Lease.WorkerFenceEpoch,
		AdmissionTaskDigest: request.AdmissionTaskDigest, TaskEvidenceDigest: request.Task.TaskEvidenceDigest,
	}}); err != nil {
		t.Fatalf("record C4 effect custody: %v", err)
	}
	now := time.Now().UnixMilli()
	receipt := GitCredentialReceipt{
		Version: gitCredentialReceiptVersion, SessionID: c4BilateralSessionID, EffectID: effectID, ModelEffectID: effectID,
		RegisteredTaskDigest: request.AdmissionTaskDigest, AuthorityProfile: c4BilateralProfile, AuthorityProfileVersion: admission.Lease.ProfileVersion,
		WorkerID: admission.Lease.WorkerID, WorkerStorageLineageID: admission.Lease.WorkerStorageLineageID, FenceEpoch: admission.Lease.WorkerFenceEpoch,
		JournalCursor: 1, JournalRecordDigest: "sha256:" + strings.Repeat("b", 64), AuthorizedAt: now, DeadlineAt: now + 60*60*1000,
	}
	credential, err := service.MintGitCredential(ctx, credentialControlToken(controlSecret, receipt.WorkerID, receipt.WorkerStorageLineageID, receipt.FenceEpoch), receipt)
	if err != nil {
		t.Fatalf("mint C4 effect credential: %v", err)
	}
	return c4BilateralAuthorityFixture{
		AuthorityStorePath: cfg.AuthorityStore,
		WorkspaceRoot:      profile.SessionIsolation.WorkspaceRoot,
		ProfileAgentID:     c4BilateralPolicyAgent,
		AgentID:            credential.AgentID,
		AgentSecret:        credential.AgentSecret,
		SessionID:          c4BilateralSessionID,
		Lease:              admission.Lease,
	}
}
