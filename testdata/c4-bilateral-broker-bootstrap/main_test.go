package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"gopkg.in/yaml.v3"

	"gh-agent-broker/internal/config"
	"gh-agent-broker/internal/sandbox"
)

const c4BilateralBootstrapTestPrincipal = "authority-worker-operator"

const c4BilateralBootstrapAdmissionTaskDigest = "sha256:4376c614c45f67ebb26180598d86409b3e1eb95a4e8a8d3c3908339c71c8a8b9"

func TestBrokerConfigEnablesCustodyTransportPrincipal(t *testing.T) {
	root := t.TempDir()
	key := filepath.Join(root, "app-private.pem")
	if err := os.WriteFile(key, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "broker.yaml")
	fixture := sandbox.C4BilateralAuthorityFixture{ProfileAgentID: "fleiglabs-repo-agent"}
	if err := writeBrokerConfig(configPath, bootstrapInputs{BackendURL: "http://c4-git-http-fixture:18080", SharedRoot: "/run/c4", PrivateKey: key, Issuer: fixtureIssuer}, fixture, filepath.Join(root, "audit.jsonl")); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := yaml.Unmarshal(encoded, &cfg); err != nil {
		t.Fatal(err)
	}
	principal, found := cfg.AgentByID(c4BilateralBootstrapTestPrincipal)
	if !found || !principal.Enabled || len(principal.Repositories) != 1 || principal.Repositories[0] != fixtureRepository {
		t.Fatalf("custody transport principal catalog entry = %+v found=%t", principal, found)
	}
}

func TestForwardedEvidenceRequiresTheCorrelatedDurableTransportRow(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	fixture, err := sandbox.BootstrapC4BilateralAuthorityFixtureForHostTest(ctx, root)
	if err != nil {
		t.Fatalf("bootstrap C4 authority fixture: %v", err)
	}
	assertHostLocalWorkspaceOwnershipAndMode(t, root)
	if fixture.AdmissionTaskDigest != c4BilateralBootstrapAdmissionTaskDigest {
		t.Fatalf("C4 fixture admission task binding = %q, want %q", fixture.AdmissionTaskDigest, c4BilateralBootstrapAdmissionTaskDigest)
	}
	store, err := sandbox.OpenAuthorityWorkerStore(ctx, fixture.AuthorityStorePath)
	if err != nil {
		t.Fatalf("open C4 authority store: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close C4 authority store: %v", closeErr)
		}
	})
	credentialAuthority, active, err := store.AuthenticateGitCredential(ctx, fixture.AgentID, fixture.AgentSecret, fixtureRepository)
	if err != nil || !active || credentialAuthority.SessionID != fixture.SessionID || credentialAuthority.RegisteredTaskDigest != fixture.AdmissionTaskDigest || credentialAuthority.TransportAuthority.Principal != c4BilateralBootstrapTestPrincipal || credentialAuthority.TransportAuthority.Profile != "general-writer-v1" {
		t.Fatalf("C4 active transport authority = %#v active:%t err:%v", credentialAuthority, active, err)
	}
	observer, err := sandbox.OpenTransportObserver(ctx, fixture.AuthorityStorePath)
	if err != nil {
		t.Fatalf("open C4 transport observer: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := observer.Close(); closeErr != nil {
			t.Errorf("close C4 transport observer: %v", closeErr)
		}
	})
	operationID := "op-" + strings.Repeat("a", 32)
	stages := []stageEvent{{OperationID: operationID, Stage: "custody_barrier_committed", Reason: "effect_credential_revalidated_and_recorded"}}

	if _, err = forwardedEvidenceFromStages(ctx, fixture.AuthorityStorePath, stages); err == nil {
		t.Fatal("forwarded evidence accepted without a durable transport row")
	}

	op := &sandbox.TransportOperation{
		OperationID:             operationID,
		Method:                  "GET",
		Service:                 "git-upload-pack",
		Repository:              fixtureRepository,
		RequestPath:             "/git/" + fixtureRepository + ".git/info/refs",
		RequestedRefs:           []string{},
		RefUpdates:              []string{},
		CredentialHeaderPresent: true,
	}
	if err = observer.ReceivedEffectCredential(ctx, fixture.AgentID, fixture.AgentSecret, fixtureRepository, credentialAuthority, op); err != nil {
		t.Fatalf("commit real C4 effect-custody transport row: %v", err)
	}
	if err = observer.Forwarded(ctx, op); err != nil {
		t.Fatalf("append real forwarded transport row: %v", err)
	}

	if _, err = forwardedEvidenceFromStages(ctx, fixture.AuthorityStorePath, []stageEvent{{OperationID: "op-" + strings.Repeat("b", 32), Stage: "custody_barrier_committed", Reason: "effect_credential_revalidated_and_recorded"}}); err == nil {
		t.Fatal("forwarded evidence accepted a row from another audit operation")
	}
	evidence, err := forwardedEvidenceFromStages(ctx, fixture.AuthorityStorePath, stages)
	if err != nil {
		t.Fatalf("project correlated forwarded transport row: %v", err)
	}
	if evidence.Version != "broker/c4-forwarded-transport/v1" || evidence.OperationID != operationID || evidence.Phase != "forwarded" || evidence.PhaseOrdinal != 2 || evidence.Method != "GET" || evidence.Service != "git-upload-pack" || evidence.Repository != fixtureRepository || evidence.RequestPath != "/git/"+fixtureRepository+".git/info/refs" || evidence.Decision != "allowed" || evidence.OutcomeCode != "" || evidence.HTTPStatus != 0 || evidence.BackendStatus != 0 {
		t.Fatalf("unsafe or uncorrelated forwarded evidence: %+v", evidence)
	}
}

func assertHostLocalWorkspaceOwnershipAndMode(t *testing.T, root string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "workspaces", "*", "*"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("C4 host-local workspace paths = %v, %v; want one", paths, err)
	}
	info, err := os.Stat(paths[0])
	if err != nil {
		t.Fatalf("stat C4 host-local workspace: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("C4 host-local workspace mode = %04o, want 0700", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() {
		t.Fatalf("C4 host-local workspace owner = %#v, want %d:%d", info.Sys(), os.Geteuid(), os.Getegid())
	}
}

func TestStagesFromAuditRejectsUncorrelatedOperationIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	validID := "op-" + strings.Repeat("c", 32)
	invalidID := "op-" + strings.Repeat("d", 32)
	contents := strings.Join([]string{
		`{"operation":"repository_transport_stage","operation_id":"` + validID + `","extra":{"request_id":"` + validID + `","stage":"custody_barrier_committed","reason":"effect_credential_revalidated_and_recorded"}}`,
		`{"operation":"repository_transport_stage","operation_id":"` + invalidID + `","extra":{"request_id":"` + validID + `","stage":"custody_barrier_committed","reason":"effect_credential_revalidated_and_recorded"}}`,
	}, "\n") + "\n"
	if err := writeAtomic(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write audit fixture: %v", err)
	}
	events, err := stagesFromAudit(path)
	if err != nil {
		t.Fatalf("read C4 audit stages: %v", err)
	}
	if len(events) != 1 || events[0].OperationID != validID {
		t.Fatalf("audit correlation projection = %#v, want only %q", events, validID)
	}
}
