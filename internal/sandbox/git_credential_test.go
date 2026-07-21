package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEffectTokenFingerprintIsDomainSeparatedHMAC(t *testing.T) {
	store, err := OpenAuthorityWorkerStore(context.Background(), filepath.Join(t.TempDir(), "authority.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close store: %v", closeErr)
		}
	})
	secret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fingerprint := store.effectTokenFingerprint(secret)
	plain := sha256.Sum256([]byte(secret))
	if fingerprint == hex.EncodeToString(plain[:]) {
		t.Fatal("effect token fingerprint used unkeyed SHA-256")
	}
	if fingerprint != store.effectTokenFingerprint(secret) || fingerprint == store.effectTokenFingerprint(secret+"x") {
		t.Fatal("effect token fingerprint is not a stable keyed verifier")
	}
}

func TestEffectCredentialRejectsTerminalCustodyAcrossRestart(t *testing.T) {
	for _, phase := range []string{"green", "escalated", "failed"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "authority.sqlite")
			store, err := OpenAuthorityWorkerStore(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			secret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			insertActiveCredentialCustody(t, store, secret)
			if _, ok, err := store.AuthenticateGitCredential(ctx, "effect-agent", secret, "grubbyhacker/repository-worker-lifecycle-test"); err != nil || !ok {
				t.Fatalf("active credential authentication = ok:%v err:%v", ok, err)
			}
			if err := store.RecordRegisteredEvents(ctx, "principal", "binding", 0, 2, []registeredEventProjection{{SessionID: "session", TurnID: "turn", ModelEffectID: "model:effect", Phase: phase, Cursor: 2, WorkerID: "worker", StorageLineageID: "storage", FenceEpoch: 1, AdmissionTaskDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}); err != nil {
				t.Fatal(err)
			}
			if _, ok, err := store.AuthenticateGitCredential(ctx, "effect-agent", secret, "grubbyhacker/repository-worker-lifecycle-test"); err != nil || ok {
				t.Fatalf("terminal credential authentication = ok:%v err:%v", ok, err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = OpenAuthorityWorkerStore(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if closeErr := store.Close(); closeErr != nil {
					t.Errorf("close store: %v", closeErr)
				}
			})
			if _, ok, err := store.AuthenticateGitCredential(ctx, "effect-agent", secret, "grubbyhacker/repository-worker-lifecycle-test"); err != nil || ok {
				t.Fatalf("replayed terminal credential authentication = ok:%v err:%v", ok, err)
			}
		})
	}
}

func TestContinuationEffectCustodyProjectsAndMintsAtomically(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	profile := cfg.AuthorityProfiles["writer"]
	profile.SessionIsolation.WorkspaceRoot = t.TempDir()
	profile.SessionIsolation.UIDStart, profile.SessionIsolation.GIDStart = os.Getuid(), os.Getgid()
	cfg.AuthorityProfiles["writer"] = profile
	const controlSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv(profile.BrokerSecretEnv, controlSecret)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	service := NewAuthorityWorkerService(cfg, store, &fakeAuthorityRuntime{}, nil, allowTestAuthorityIssuance{})
	service.newID = func() (string, error) { return "continuation-worker", nil }
	worker, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", worker.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	request := registeredRequest(t, "continuation-work", "continuation-route")
	admission, err := service.AcquireRegisteredSession(ctx, "coordinator", request)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID, rootEffect, continuationEffect = "session-continuation", "model:root", "model:continuation"
	if err = store.BindAgentdSession(ctx, request.SessionBinding, sessionID); err != nil {
		t.Fatal(err)
	}
	if err = store.RecordRegisteredTurn(ctx, "coordinator", request.SessionBinding, request.IdempotencyKey, registeredTurnState{SessionID: sessionID, TurnID: "turn:" + request.IdempotencyKey, ModelEffectID: rootEffect, SubmitCursor: 1}); err != nil {
		t.Fatal(err)
	}
	event := func(cursor int64, effect, phase string) registeredEventProjection {
		return registeredEventProjection{Cursor: cursor, SessionID: sessionID, TurnID: "turn:" + request.IdempotencyKey, ModelEffectID: effect, Phase: phase, WorkerID: admission.Lease.WorkerID, StorageLineageID: admission.Lease.WorkerStorageLineageID, FenceEpoch: admission.Lease.WorkerFenceEpoch, AdmissionTaskDigest: request.AdmissionTaskDigest, TaskEvidenceDigest: request.Task.TaskEvidenceDigest}
	}
	if err = store.RecordRegisteredEvents(ctx, "coordinator", request.SessionBinding, 0, 1, []registeredEventProjection{event(1, rootEffect, "completed")}); err != nil {
		t.Fatal(err)
	}
	wrongFence := event(2, continuationEffect, "authorized")
	wrongFence.FenceEpoch++
	if err = store.RecordRegisteredEvents(ctx, "coordinator", request.SessionBinding, 1, 2, []registeredEventProjection{wrongFence}); err == nil {
		t.Fatal("wrong fence continuation was projected")
	}
	wrongTask := event(2, continuationEffect, "authorized")
	wrongTask.TaskEvidenceDigest = "sha256:" + strings.Repeat("b", 64)
	if err = store.RecordRegisteredEvents(ctx, "coordinator", request.SessionBinding, 1, 2, []registeredEventProjection{wrongTask}); err == nil {
		t.Fatal("wrong task continuation was projected")
	}
	if err = store.RecordRegisteredEvents(ctx, "coordinator", "session:other-work", 1, 2, []registeredEventProjection{event(2, continuationEffect, "authorized")}); err == nil {
		t.Fatal("wrong binding continuation was projected")
	}
	state, err := store.RegisteredTurn(ctx, "coordinator", request.SessionBinding)
	if err != nil || state.EventsAfter != 1 {
		t.Fatalf("rejected projection advanced cursor: state=%+v err=%v", state, err)
	}
	var projected int
	if err = store.db.QueryRowContext(ctx, `SELECT count(*) FROM authority_effect_custody WHERE principal=? AND binding_digest=? AND model_effect_id=?`, "coordinator", admission.Lease.BindingDigest, continuationEffect).Scan(&projected); err != nil || projected != 0 {
		t.Fatalf("rejected projection created continuation custody: count=%d err=%v", projected, err)
	}
	if err = store.RecordRegisteredEvents(ctx, "coordinator", request.SessionBinding, 1, 2, []registeredEventProjection{event(2, continuationEffect, "authorized")}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	receipt := GitCredentialReceipt{Version: gitCredentialReceiptVersion, SessionID: sessionID, EffectID: continuationEffect, ModelEffectID: continuationEffect, RegisteredTaskDigest: request.AdmissionTaskDigest, AuthorityProfile: admission.Lease.Profile, AuthorityProfileVersion: admission.Lease.ProfileVersion, WorkerID: admission.Lease.WorkerID, WorkerStorageLineageID: admission.Lease.WorkerStorageLineageID, FenceEpoch: admission.Lease.WorkerFenceEpoch, JournalCursor: 2, JournalRecordDigest: "sha256:" + strings.Repeat("c", 64), AuthorizedAt: now, DeadlineAt: now + 60*60*1000}
	control := credentialControlToken(controlSecret, receipt.WorkerID, receipt.WorkerStorageLineageID, receipt.FenceEpoch)
	if _, err = service.MintGitCredential(ctx, control, receipt); err != nil {
		t.Fatalf("continuation credential mint: %v", err)
	}
	replay := receipt
	replay.JournalCursor++
	if _, err = service.MintGitCredential(ctx, control, replay); err == nil {
		t.Fatal("distinct continuation receipt replay minted twice")
	}
	if err = store.RecordRegisteredEvents(ctx, "coordinator", request.SessionBinding, 2, 3, []registeredEventProjection{event(3, continuationEffect, "completed")}); err != nil {
		t.Fatal(err)
	}
	if _, err = service.MintGitCredential(ctx, control, receipt); err == nil {
		t.Fatal("terminal continuation receipt replay minted")
	}
}

func insertActiveCredentialCustody(t *testing.T, store *AuthorityWorkerStore, secret string) {
	t.Helper()
	ctx := context.Background()
	now := formatAuthorityTime(time.Now().UTC())
	const principal, worker, profile, task, effect = "principal", "worker", "profile", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "model:effect"
	binding := store.requestDigest("binding")
	for _, query := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO authority_workers(worker_id,profile,profile_version,policy_digest,image_reference,generation,state,capacity,created_at,updated_at,worker_storage_lineage_id,worker_fence_epoch) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, []any{worker, profile, "version", "policy", "image", 1, AuthorityWorkerReady, 1, now, now, "storage", 1}},
		{`INSERT INTO authority_session_leases(principal,profile,idempotency_digest,request_fingerprint,binding_digest,worker_id,created_at,session_lineage_id) VALUES(?,?,?,?,?,?,?,?)`, []any{principal, profile, "idem", "request", binding, worker, now, "lineage"}},
		{`INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,session_lineage_id,agentd_session_id) VALUES(?,?,?,?,?,?,?,?)`, []any{binding, worker, 1, 1, "/workspace", now, "lineage", "session"}},
		{`INSERT INTO authority_registered_admissions(principal,binding_digest,protocol_version,work_item_id,route_snapshot_id,canonical_task_json,admission_task_digest) VALUES(?,?,?,?,?,?,?)`, []any{principal, binding, coordinatorRegisteredProtocolVersion, "work", "route", `{}`, task}},
		{`INSERT INTO authority_registered_turns(principal,binding_digest,idempotency_digest,session_id,turn_id,model_effect_id,submit_cursor) VALUES(?,?,?,?,?,?,?)`, []any{principal, binding, "idem", "session", "turn", effect, 1}},
		{`INSERT INTO authority_effect_custody(principal,binding_digest,model_effect_id,session_id,worker_id,worker_storage_lineage_id,worker_fence_epoch,authority_profile,authority_profile_version,policy_digest,registered_task_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, []any{principal, binding, effect, "session", worker, "storage", 1, profile, "version", "policy", task}},
		{`INSERT INTO authority_git_credentials(receipt_digest,receipt_json,principal,binding_digest,session_id,effect_id,model_effect_id,repository,worker_id,worker_storage_lineage_id,worker_fence_epoch,agent_id,secret_fingerprint,expires_at_ms,authority_profile,authority_profile_version,registered_task_digest,journal_cursor,journal_record_digest,authorized_at_ms,deadline_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, []any{"sha256:" + strings.Repeat("b", 64), `{}`, principal, binding, "session", effect, effect, "grubbyhacker/repository-worker-lifecycle-test", worker, "storage", 1, "effect-agent", store.effectTokenFingerprint(secret), time.Now().Add(time.Hour).UnixMilli(), profile, "version", task, 1, "sha256:" + strings.Repeat("c", 64), time.Now().UnixMilli(), time.Now().Add(time.Hour).UnixMilli()}},
	} {
		if _, err := store.db.ExecContext(ctx, query.query, query.args...); err != nil {
			t.Fatal(err)
		}
	}
}
