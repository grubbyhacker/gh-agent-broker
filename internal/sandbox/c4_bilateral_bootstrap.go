package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gh-agent-broker/internal/pushtripwire"
)

// C4BilateralAuthorityFixture is the sole broker-owned seed result consumed
// by the C4 bootstrap image. It intentionally exposes only the effect
// credential projection required by the native agentd child; the control
// secret, receipt, and authority-store internals remain private.
type C4BilateralAuthorityFixture struct {
	AuthorityStorePath  string
	ProfileAgentID      string
	AgentID             string
	AgentSecret         string
	SessionID           string
	AdmissionTaskDigest string
}

const (
	c4BilateralBootstrapProfile   = "general-writer-v1"
	c4BilateralBootstrapPrincipal = "authority-worker-operator"
	c4BilateralBootstrapAgent     = "fleiglabs-repo-agent"
	c4BilateralBootstrapSession   = "agentd-c4-bilateral-session"
	c4BilateralBootstrapRepo      = "grubbyhacker/repository-worker-lifecycle-test"
	// The real C4 Docker fixture launches the native agentd child through its
	// setuid launcher as this non-system session identity. Keep this fixed for
	// the runtime fixture; host-local unit tests use their effective identity
	// through the explicitly test-only entry point below.
	c4BilateralRuntimeSessionUID = 20000
	c4BilateralRuntimeSessionGID = 20000
	// c4BilateralAdmissionTaskDigest is the SHA-256 of the fixed registered
	// task emitted by c4BilateralRegisteredRequest. It is intentionally an
	// exact fixture binding, not a caller-derived value.
	c4BilateralAdmissionTaskDigest = "sha256:4376c614c45f67ebb26180598d86409b3e1eb95a4e8a8d3c3908339c71c8a8b9"
	c4BilateralControlSecretEnv    = "C4_BILATERAL_INTERNAL_CONTROL_SECRET"
)

// BootstrapC4BilateralAuthorityFixture creates the C4 authority state only
// through the broker's authority-store APIs. It must never be used for a
// product or production configuration: its fixed identities deliberately
// exercise the control-principal versus policy-agent regression predicate.
func BootstrapC4BilateralAuthorityFixture(ctx context.Context, root string) (C4BilateralAuthorityFixture, error) {
	return bootstrapC4BilateralAuthorityFixture(ctx, root, c4BilateralRuntimeSessionUID, c4BilateralRuntimeSessionGID)
}

// BootstrapC4BilateralAuthorityFixtureForHostTest creates the same C4
// authority state with the effective host identity. It exists only because a
// host-local unit test cannot chown its temporary directory to the fixture's
// isolated Docker session identity. The real Docker fixture must use
// BootstrapC4BilateralAuthorityFixture so its uid_gid_0700 contract remains
// 20000:20000.
func BootstrapC4BilateralAuthorityFixtureForHostTest(ctx context.Context, root string) (C4BilateralAuthorityFixture, error) {
	return bootstrapC4BilateralAuthorityFixture(ctx, root, os.Geteuid(), os.Getegid())
}

func bootstrapC4BilateralAuthorityFixture(ctx context.Context, root string, sessionUID, sessionGID int) (C4BilateralAuthorityFixture, error) {
	if !filepath.IsAbs(root) {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("C4 fixture root must be absolute")
	}
	if sessionUID < 0 || sessionGID < 0 {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("C4 fixture session identity is invalid")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("create C4 fixture root: %w", err)
	}
	controlSecret, err := c4RandomHex(32)
	if err != nil {
		return C4BilateralAuthorityFixture{}, err
	}
	if err = os.Setenv(c4BilateralControlSecretEnv, controlSecret); err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("set C4 internal control secret: %w", err)
	}

	storePath := filepath.Join(root, "authority-workers.sqlite")
	if _, statErr := os.Stat(storePath); !os.IsNotExist(statErr) {
		if statErr == nil {
			return C4BilateralAuthorityFixture{}, fmt.Errorf("C4 authority store already exists")
		}
		return C4BilateralAuthorityFixture{}, fmt.Errorf("stat C4 authority store: %w", statErr)
	}
	cfg := c4BilateralBootstrapConfig(root, storePath, sessionUID, sessionGID)
	store, err := OpenAuthorityWorkerStore(ctx, storePath)
	if err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("open C4 authority store: %w", err)
	}
	defer store.Close()
	issuance, err := pushtripwire.Open(storePath)
	if err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("open C4 issuance store: %w", err)
	}
	defer issuance.Close()
	if err = issuance.ReplaceEnforcementCatalog(ctx, map[string]int64{c4BilateralBootstrapProfile: 1}); err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("register C4 issuance catalog: %w", err)
	}

	service := NewAuthorityWorkerService(cfg, store, c4BilateralSeedRuntime{}, nil, issuance)
	service.newID = func() (string, error) { return "c4-bilateral-worker", nil }
	worker, err := service.Provision(ctx, c4BilateralBootstrapPrincipal, c4BilateralBootstrapProfile)
	if err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("provision C4 authority worker: %w", err)
	}
	if _, err = service.SetHealth(ctx, c4BilateralBootstrapPrincipal, worker.WorkerID, "c4_fixture_ready", true); err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("ready C4 authority worker: %w", err)
	}

	request := c4BilateralRegisteredRequest()
	validated, err := validateRegisteredAdmission(request)
	if err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("validate C4 registered admission: %w", err)
	}
	admission, err := service.AcquireRegisteredSession(ctx, c4BilateralBootstrapPrincipal, request)
	if err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("acquire C4 authority lease: %w", err)
	}
	if err = store.BindAgentdSession(ctx, request.SessionBinding, c4BilateralBootstrapSession); err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("bind C4 agentd session: %w", err)
	}
	effectID := "model:c4-bilateral-effect"
	if err = store.RecordRegisteredTurn(ctx, c4BilateralBootstrapPrincipal, request.SessionBinding, request.IdempotencyKey, registeredTurnState{
		SessionID: c4BilateralBootstrapSession, TurnID: "turn:c4-bilateral", ModelEffectID: effectID, SubmitCursor: 1,
	}); err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("record C4 registered turn: %w", err)
	}
	if err = store.RecordRegisteredEvents(ctx, c4BilateralBootstrapPrincipal, request.SessionBinding, 0, 1, []registeredEventProjection{{
		Cursor: 1, SessionID: c4BilateralBootstrapSession, TurnID: "turn:c4-bilateral", ModelEffectID: effectID, Phase: "authorized",
		WorkerID: admission.Lease.WorkerID, StorageLineageID: admission.Lease.WorkerStorageLineageID, FenceEpoch: admission.Lease.WorkerFenceEpoch,
		AdmissionTaskDigest: request.AdmissionTaskDigest, TaskEvidenceDigest: request.Task.TaskEvidenceDigest,
	}}); err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("record C4 effect custody: %w", err)
	}
	now := time.Now().UnixMilli()
	credential, err := service.MintGitCredential(ctx, credentialControlToken(controlSecret, admission.Lease.WorkerID, admission.Lease.WorkerStorageLineageID, admission.Lease.WorkerFenceEpoch), GitCredentialReceipt{
		Version: gitCredentialReceiptVersion, SessionID: c4BilateralBootstrapSession, EffectID: effectID, ModelEffectID: effectID,
		RegisteredTaskDigest: request.AdmissionTaskDigest, AuthorityProfile: c4BilateralBootstrapProfile, AuthorityProfileVersion: admission.Lease.ProfileVersion,
		WorkerID: admission.Lease.WorkerID, WorkerStorageLineageID: admission.Lease.WorkerStorageLineageID, FenceEpoch: admission.Lease.WorkerFenceEpoch,
		JournalCursor: 1, JournalRecordDigest: "sha256:" + strings.Repeat("b", 64), AuthorizedAt: now, DeadlineAt: now + 60*60*1000,
	})
	if err != nil {
		return C4BilateralAuthorityFixture{}, fmt.Errorf("mint C4 effect credential: %w", err)
	}
	return C4BilateralAuthorityFixture{AuthorityStorePath: storePath, ProfileAgentID: c4BilateralBootstrapAgent, AgentID: credential.AgentID, AgentSecret: credential.AgentSecret, SessionID: c4BilateralBootstrapSession, AdmissionTaskDigest: validated.Digest}, nil
}

func c4BilateralBootstrapConfig(root, storePath string, sessionUID, sessionGID int) Config {
	return Config{
		AuthorityStore: storePath,
		Repositories:   []string{c4BilateralBootstrapRepo},
		Networks:       map[string]NetworkPolicy{"c4": {Network: "c4-bilateral-git-transport"}},
		AuthorityProfiles: map[string]AuthorityProfile{c4BilateralBootstrapProfile: {
			Image: "c4-bilateral-seed@sha256:" + strings.Repeat("c", 64), IssuanceGeneration: 1, Platform: "linux/amd64", Command: fixedAgentdCommand,
			Resources: Resources{CPUShares: 128, MemoryMB: 512, PidsLimit: 128}, NetworkPolicy: "c4", BrokerAgentID: c4BilateralBootstrapAgent,
			BrokerSecretEnv: c4BilateralControlSecretEnv, CoordinatorTokenEnv: "C4_BILATERAL_UNUSED_COORDINATOR_TOKEN",
			Repositories: []string{c4BilateralBootstrapRepo}, BranchPolicy: BranchPolicy{AllowedPatterns: []string{`^agent/fleiglabs-repo-agent/[a-z0-9][a-z0-9-]{0,62}$`}, BaseBranches: []string{"main"}, GeneratePrefix: "agent/fleiglabs-repo-agent"},
			Operations: []string{"git.upload-pack", "git.receive-pack"}, MaxWorkers: 1, SessionCapacity: 1,
			SessionIsolation: SessionIsolation{Primitive: "uid_gid_0700", WorkspaceRoot: filepath.Join(root, "workspaces"), UIDStart: sessionUID, GIDStart: sessionGID},
			Checkpoint:       CheckpointPolicy{Directory: filepath.Join(root, "checkpoints"), KeyEnv: "C4_BILATERAL_UNUSED_CHECKPOINT_KEY"},
			Storage:          AuthorityStorage{SessionVolume: "c4-sessions", CheckpointVolume: "c4-checkpoints", EvidenceVolume: "c4-evidence"},
		}},
		AuthorityPrincipals: map[string]AuthorityPrincipal{c4BilateralBootstrapPrincipal: {
			Token: "c4-bilateral-authority-operator", AllowedProfiles: []string{c4BilateralBootstrapProfile}, AllowedActions: []string{"provision", "health", "acquire"},
		}},
		RegisteredCoordinatorPrincipal: c4BilateralBootstrapPrincipal,
	}
}

func c4BilateralRegisteredRequest() RegisteredAdmissionRequest {
	return RegisteredAdmissionRequest{
		Version: coordinatorRegisteredProtocolVersion, Profile: c4BilateralBootstrapProfile, IdempotencyKey: "c4-bilateral-key", SessionBinding: "session:c4-bilateral-work",
		Source:              RegisteredTaskSource{WorkItemID: "c4-bilateral-work", RouteSnapshotID: "c4-bilateral-route"},
		Task:                RegisteredTask{TaskKind: "github_green_pr_v1", TaskVersion: "1.0.0", CompletionContract: "github_green_pr_v1", VerifierID: "github_green_pr_v1", ContractDigest: githubGreenPRContractDigest, TaskEvidenceDigest: "sha256:" + strings.Repeat("a", 64), Parameters: RegisteredTaskParameters{Repository: c4BilateralBootstrapRepo, BaseBranch: "main", BranchRef: "agent/fleiglabs-repo-agent/fixture"}},
		AdmissionTaskDigest: c4BilateralAdmissionTaskDigest,
	}
}

type c4BilateralSeedRuntime struct{}

func (c4BilateralSeedRuntime) Create(context.Context, AuthorityWorkerSpec) (AuthorityRuntimeResult, error) {
	return AuthorityRuntimeResult{ContainerID: "c4-bilateral-authority-worker", ImageDigest: "sha256:" + strings.Repeat("c", 64)}, nil
}
func (c4BilateralSeedRuntime) Stop(context.Context, string) error { return nil }
func (c4BilateralSeedRuntime) Healthy(context.Context, string) (bool, string, error) {
	return true, "c4_fixture_ready", nil
}

func c4RandomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read C4 fixture randomness: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
