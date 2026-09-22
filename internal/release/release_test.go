package release

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

const (
	digestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	digestC = "sha256:3333333333333333333333333333333333333333333333333333333333333333"

	refA = "ghcr.io/example/youknowme-curator-agent:sha-aaa@" + digestA
	refB = "ghcr.io/example/youknowme-curator-agent:sha-bbb@" + digestB
	refC = "ghcr.io/example/youknowme-curator-agent:sha-ccc@" + digestC

	agentType = "youknowme-curator"
	actor     = "test-actor"
)

func testProvenance() Provenance {
	return Provenance{
		SourceRevision:           "cafebabecafebabecafebabecafebabecafebabe",
		DependencyManifestSHA256: "deadbeef",
		Platform:                 "linux/amd64",
	}
}

func testRequirements() Requirements {
	return Requirements{
		ProvenanceFields: []string{"image_digest", "source_revision", "dependency_manifest_sha256"},
		Platforms:        []string{"linux/amd64"},
	}
}

func openStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "releases.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return store
}

// promoted publishes, verifies, acquires and promotes one release.
func promoted(t *testing.T, store *Store, reference string) Release {
	t.Helper()
	ctx := context.Background()
	item, err := store.PublishCandidate(ctx, agentType, reference, testProvenance(), actor)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := store.verify(ctx, item.Generation, testRequirements(), actor); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := store.markAvailable(ctx, item.Generation, true, actor); err != nil {
		t.Fatalf("mark available: %v", err)
	}
	if err := store.Promote(ctx, item.Generation, actor); err != nil {
		t.Fatalf("promote: %v", err)
	}
	return item
}

func TestPublishRequiresDigestPinnedReference(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	for _, reference := range []string{
		"ghcr.io/example/agent:latest",
		"ghcr.io/example/agent:sha-abc",
		"ghcr.io/example/agent",
		"ghcr.io/example/agent@sha256:short",
	} {
		if _, err := store.PublishCandidate(ctx, agentType, reference, testProvenance(), actor); err == nil {
			t.Fatalf("expected %q to be refused as not digest-pinned", reference)
		}
	}

	if _, err := store.PublishCandidate(ctx, agentType, refA, testProvenance(), actor); err != nil {
		t.Fatalf("digest-pinned reference should be accepted: %v", err)
	}
}

func TestPublishedCandidateIsNotRunnable(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	if _, err := store.PublishCandidate(ctx, agentType, refA, testProvenance(), actor); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := store.Resolve(ctx, agentType); !errors.Is(err, ErrNoActiveRelease) {
		t.Fatalf("a published candidate must not resolve, got %v", err)
	}
}

func TestPromotionRequiresVerificationAndAvailability(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	item, err := store.PublishCandidate(ctx, agentType, refA, testProvenance(), actor)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	if err := store.Promote(ctx, item.Generation, actor); !errors.Is(err, ErrNotPromotable) {
		t.Fatalf("unverified release must not promote, got %v", err)
	}

	if err := store.verify(ctx, item.Generation, testRequirements(), actor); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := store.Promote(ctx, item.Generation, actor); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unacquired release must not promote, got %v", err)
	}

	if err := store.markAvailable(ctx, item.Generation, true, actor); err != nil {
		t.Fatalf("mark available: %v", err)
	}
	if err := store.Promote(ctx, item.Generation, actor); err != nil {
		t.Fatalf("verified and acquired release should promote: %v", err)
	}
}

func TestVerifyEnforcesRequirements(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	incomplete := testProvenance()
	incomplete.DependencyManifestSHA256 = ""
	item, err := store.PublishCandidate(ctx, agentType, refA, incomplete, actor)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := store.verify(ctx, item.Generation, testRequirements(), actor); err == nil {
		t.Fatal("missing provenance field must fail verification")
	}

	wrongPlatform := testProvenance()
	wrongPlatform.Platform = "linux/s390x"
	other, err := store.PublishCandidate(ctx, agentType, refB, wrongPlatform, actor)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := store.verify(ctx, other.Generation, testRequirements(), actor); err == nil {
		t.Fatal("unsupported platform must fail verification")
	}
}

func TestPromotionIsMonotonicByGeneration(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	first := promoted(t, store, refA)
	second := promoted(t, store, refB)
	if second.Generation <= first.Generation {
		t.Fatalf("generations must increase: %d then %d", first.Generation, second.Generation)
	}

	// The superseded generation cannot be re-promoted; that is rollback's job.
	if err := store.Promote(ctx, first.Generation, actor); err == nil {
		t.Fatal("re-promoting an older generation must be refused")
	}

	active, err := store.Active(ctx, agentType)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if active.Generation != second.Generation {
		t.Fatalf("expected generation %d active, got %d", second.Generation, active.Generation)
	}
}

func TestRollbackIsSeparateAndAudited(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	first := promoted(t, store, refA)
	second := promoted(t, store, refB)

	if err := store.Rollback(ctx, agentType, first.Generation, actor); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	active, err := store.Active(ctx, agentType)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if active.Generation != first.Generation {
		t.Fatalf("expected rollback target %d active, got %d", first.Generation, active.Generation)
	}

	retired, err := store.Get(ctx, second.Generation)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if retired.State != StateRolledBack {
		t.Fatalf("expected rolled-back state, got %q", retired.State)
	}

	trail, err := store.AuditTrail(ctx, first.Generation)
	if err != nil {
		t.Fatalf("audit trail: %v", err)
	}
	operations := make([]string, 0, len(trail))
	for _, entry := range trail {
		operations = append(operations, entry.Operation)
	}
	want := []string{OperationPublish, OperationVerify, OperationAcquire, OperationPromote, OperationRollback}
	if len(operations) != len(want) {
		t.Fatalf("expected audit %v, got %v", want, operations)
	}
	for index, operation := range want {
		if operations[index] != operation {
			t.Fatalf("expected audit %v, got %v", want, operations)
		}
	}
}

func TestRollbackRefusesUnavailableTarget(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	first := promoted(t, store, refA)
	promoted(t, store, refB)

	if err := store.markAvailable(ctx, first.Generation, false, actor); err != nil {
		t.Fatalf("evict: %v", err)
	}
	if err := store.Rollback(ctx, agentType, first.Generation, actor); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("rollback to an absent image must be refused, got %v", err)
	}
}

func TestResolveFailsClosedWhenImageIsAbsent(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	item := promoted(t, store, refA)
	if _, err := store.Resolve(ctx, agentType); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Simulate a prune or a restore onto a host without the image.
	if err := store.markAvailable(ctx, item.Generation, false, actor); err != nil {
		t.Fatalf("evict: %v", err)
	}
	if _, err := store.Resolve(ctx, agentType); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("resolve must fail closed when the image is absent, got %v", err)
	}

	// The release is still active; only its availability changed.
	active, err := store.Active(ctx, agentType)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if active.Generation != item.Generation {
		t.Fatalf("active generation should be unchanged, got %d", active.Generation)
	}
}

func TestReconcileMarksMissingImagesAndReportsThem(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	item := promoted(t, store, refA)

	absent := func(context.Context, string, string) (bool, error) { return false, nil }
	missing, err := store.Reconcile(ctx, absent, actor)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(missing) != 1 || missing[0].Generation != item.Generation {
		t.Fatalf("expected generation %d reported missing, got %+v", item.Generation, missing)
	}
	if _, err := store.Resolve(ctx, agentType); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("after reconcile the release must fail closed, got %v", err)
	}

	present := func(context.Context, string, string) (bool, error) { return true, nil }
	recovered, err := store.Reconcile(ctx, present, actor)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(recovered) != 0 {
		t.Fatalf("expected nothing missing after reacquisition, got %+v", recovered)
	}
	if _, err := store.Resolve(ctx, agentType); err != nil {
		t.Fatalf("resolve should succeed once the image is available again: %v", err)
	}
}

func TestReconcileRequiresACheckAndActor(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	if _, err := store.Reconcile(ctx, nil, actor); err == nil {
		t.Fatal("reconcile without an availability check must fail")
	}
	present := func(context.Context, string, string) (bool, error) { return true, nil }
	if _, err := store.Reconcile(ctx, present, ""); err == nil {
		t.Fatal("reconcile without an actor must fail")
	}
}

func TestOperationsRequireAnActor(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	if _, err := store.PublishCandidate(ctx, agentType, refA, testProvenance(), ""); err == nil {
		t.Fatal("publish without an actor must fail")
	}
	item, err := store.PublishCandidate(ctx, agentType, refA, testProvenance(), actor)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := store.verify(ctx, item.Generation, testRequirements(), ""); err == nil {
		t.Fatal("verify without an actor must fail")
	}
	if err := store.markAvailable(ctx, item.Generation, true, ""); err == nil {
		t.Fatal("availability change without an actor must fail")
	}
	if err := store.Promote(ctx, item.Generation, ""); err == nil {
		t.Fatal("promote without an actor must fail")
	}
	if err := store.Rollback(ctx, agentType, item.Generation, ""); err == nil {
		t.Fatal("rollback without an actor must fail")
	}
}

func TestDuplicateDigestForSameAgentTypeIsRefused(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	if _, err := store.PublishCandidate(ctx, agentType, refA, testProvenance(), actor); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := store.PublishCandidate(ctx, agentType, refA, testProvenance(), actor); err == nil {
		t.Fatal("republishing the same digest for one agent type must be refused")
	}
}

func TestAgentTypesAreIsolated(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	promoted(t, store, refA)

	other, err := store.PublishCandidate(ctx, "other-agent", refC, testProvenance(), actor)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := store.verify(ctx, other.Generation, testRequirements(), actor); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := store.markAvailable(ctx, other.Generation, true, actor); err != nil {
		t.Fatalf("mark available: %v", err)
	}
	if err := store.Promote(ctx, other.Generation, actor); err != nil {
		t.Fatalf("promote: %v", err)
	}

	first, err := store.Resolve(ctx, agentType)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	second, err := store.Resolve(ctx, "other-agent")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if first.ImageDigest == second.ImageDigest {
		t.Fatal("distinct agent types must resolve to distinct releases")
	}
}

func TestRollbackRejectsCrossTypeGeneration(t *testing.T) {
	store := openStore(t)
	ctx := context.Background()

	item := promoted(t, store, refA)
	if err := store.Rollback(ctx, "other-agent", item.Generation, actor); err == nil {
		t.Fatal("rollback must refuse a generation belonging to another agent type")
	}
}

func TestStoreRequiresAbsolutePath(t *testing.T) {
	if _, err := Open(context.Background(), "relative/releases.sqlite"); err == nil {
		t.Fatal("a relative store path must be refused")
	}
}

func TestRegistrySurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "releases.sqlite")

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	item := promoted(t, store, refA)
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened store: %v", err)
		}
	}()

	active, err := reopened.Active(ctx, agentType)
	if err != nil {
		t.Fatalf("active after reopen: %v", err)
	}
	if active.Generation != item.Generation {
		t.Fatalf("expected generation %d after reopen, got %d", item.Generation, active.Generation)
	}
}
