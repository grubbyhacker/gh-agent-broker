package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
			if err := store.RecordRegisteredEvents(ctx, "principal", "binding", 0, 2, []registeredEventProjection{{Phase: phase, Cursor: 2}}); err != nil {
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
		{`INSERT INTO authority_effect_custody(principal,binding_digest,model_effect_id) VALUES(?,?,?)`, []any{principal, binding, effect}},
		{`INSERT INTO authority_git_credentials(receipt_digest,receipt_json,principal,binding_digest,session_id,effect_id,model_effect_id,repository,worker_id,worker_storage_lineage_id,worker_fence_epoch,agent_id,secret_fingerprint,expires_at_ms,authority_profile,authority_profile_version,registered_task_digest,journal_cursor,journal_record_digest,authorized_at_ms,deadline_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, []any{"sha256:" + strings.Repeat("b", 64), `{}`, principal, binding, "session", effect, effect, "grubbyhacker/repository-worker-lifecycle-test", worker, "storage", 1, "effect-agent", store.effectTokenFingerprint(secret), time.Now().Add(time.Hour).UnixMilli(), profile, "version", task, 1, "sha256:" + strings.Repeat("c", 64), time.Now().UnixMilli(), time.Now().Add(time.Hour).UnixMilli()}},
	} {
		if _, err := store.db.ExecContext(ctx, query.query, query.args...); err != nil {
			t.Fatal(err)
		}
	}
}
