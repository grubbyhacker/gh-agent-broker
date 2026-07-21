package sandbox

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestTransportEventsFailClosedAndAppendOnly(t *testing.T) {
	ctx := context.Background()
	observer, err := OpenTransportObserver(ctx, filepath.Join(t.TempDir(), "authority-workers.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTransportObserver(observer) })
	seedTransportLease(t, observer.store, "writer", "worker-1", "binding-1")

	if count, err := observer.transportEventCount(ctx); err != nil || count != 0 {
		t.Fatalf("no-op count=%d err=%v", count, err)
	}
	authority, err := observer.ResolveAuthority(ctx, "writer")
	if err != nil || authority.WorkerID != "worker-1" {
		t.Fatalf("internally resolved authority=%+v err=%v", authority, err)
	}
	op := TransportOperation{OperationID: "operation-1", Method: "GET", Service: "git-upload-pack", Repository: "local/repo", RequestPath: "/git/local/repo.git/info/refs", RequestedRefs: []string{}, RefUpdates: []any{}, Authority: authority}
	if err := observer.Received(ctx, &op); err != nil {
		t.Fatal(err)
	}
	if count, err := observer.transportEventCount(ctx); err != nil || count != 1 {
		t.Fatalf("incomplete received chain count=%d err=%v", count, err)
	}
	if err := observer.Received(ctx, &op); err == nil {
		t.Fatal("replayed received phase was accepted")
	}
	if err := observer.Forwarded(ctx, &op); err != nil {
		t.Fatal(err)
	}
	if err := observer.Terminal(ctx, &op, "completed", "allowed", "", 200, 200); err != nil {
		t.Fatal(err)
	}

	denied := TransportOperation{OperationID: "operation-2", Method: "GET", Service: "git-upload-pack", Repository: "local/repo", RequestPath: "/git/local/repo.git/info/refs", RequestedRefs: []string{}, RefUpdates: []any{}, Authority: authority}
	if err := observer.Received(ctx, &denied); err != nil {
		t.Fatal(err)
	}
	if err := observer.Terminal(ctx, &denied, "denied", "denied", "policy_denied", 403, 0); err != nil {
		t.Fatal(err)
	}

	failed := TransportOperation{OperationID: "operation-3", Method: "POST", Service: "git-receive-pack", Repository: "local/repo", RequestPath: "/git/local/repo.git/git-receive-pack", RequestedRefs: []string{}, RefUpdates: []any{}, Authority: authority}
	if err := observer.Received(ctx, &failed); err != nil {
		t.Fatal(err)
	}
	if err := observer.Forwarded(ctx, &failed); err != nil {
		t.Fatal(err)
	}
	if err := observer.Terminal(ctx, &failed, "failed", "failed", "backend_unavailable", 502, 0); err != nil {
		t.Fatal(err)
	}
	rows, err := observer.store.db.Query(`SELECT cursor,previous_event_digest,event_digest FROM repository_transport_events ORDER BY cursor`)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransportRows(rows)
	var previous string
	var cursor int
	for rows.Next() {
		var gotPrevious, digest string
		if err := rows.Scan(&cursor, &gotPrevious, &digest); err != nil {
			t.Fatal(err)
		}
		if gotPrevious != previous {
			t.Fatalf("cursor %d previous digest=%q want %q", cursor, gotPrevious, previous)
		}
		previous = digest
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	seedTransportLease(t, observer.store, "writer", "worker-2", "binding-2")
	if _, err := observer.ResolveAuthority(ctx, "writer"); err == nil {
		t.Fatal("ambiguous active authority was accepted")
	}
}

func TestGreenPRAdmissionUsesOnlyRegisteredTaskAndCompletedPush(t *testing.T) {
	ctx := context.Background()
	observer, err := OpenTransportObserver(ctx, filepath.Join(t.TempDir(), "authority-workers.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTransportObserver(observer) })
	seedTransportLease(t, observer.store, "writer", "worker-1", "session:transport-work")
	request := registeredRequest(t, "transport-work", "transport-route")
	admission, err := validateRegisteredAdmission(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observer.store.db.ExecContext(ctx, `INSERT INTO authority_registered_admissions(principal,binding_digest,protocol_version,work_item_id,route_snapshot_id,canonical_task_json,admission_task_digest) VALUES(?,?,?,?,?,?,?)`, "broker-principal", "session:transport-work", coordinatorRegisteredProtocolVersion, request.Source.WorkItemID, request.Source.RouteSnapshotID, admission.CanonicalJSON, admission.Digest); err != nil {
		t.Fatal(err)
	}
	authority, err := observer.ResolveAuthority(ctx, "writer")
	if err != nil {
		t.Fatal(err)
	}
	updates, err := json.Marshal([]struct {
		After string `json:"After"`
		Ref   string `json:"Ref"`
	}{{After: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Ref: "refs/heads/agent/fleiglabs-repo-agent/settled"}})
	if err != nil {
		t.Fatal(err)
	}
	op := TransportOperation{OperationID: "push-1", Method: "POST", Service: "git-receive-pack", Repository: request.Task.Parameters.RepositoryID, RequestPath: "/git/repo.git/git-receive-pack", RequestedRefs: []string{}, RefUpdates: json.RawMessage(updates), Authority: authority}
	if err := observer.Received(ctx, &op); err != nil {
		t.Fatal(err)
	}
	if err := observer.Forwarded(ctx, &op); err != nil {
		t.Fatal(err)
	}
	if err := observer.Terminal(ctx, &op, "completed", "allowed", "", 200, 200); err != nil {
		t.Fatal(err)
	}
	got, err := observer.GreenPRAdmission(ctx, "writer")
	if err != nil || got.OperationID != "push-1" || got.PushedSHA != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || got.TaskDigest != admission.Digest {
		t.Fatalf("admission=%+v err=%v", got, err)
	}
}

func closeTransportObserver(observer *TransportObserver) {
	if err := observer.Close(); err != nil {
		return
	}
}

func TestTransportAppendFailureDoesNotSucceed(t *testing.T) {
	ctx := context.Background()
	observer, err := OpenTransportObserver(ctx, filepath.Join(t.TempDir(), "authority-workers.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	seedTransportLease(t, observer.store, "writer", "worker-1", "binding-1")
	authority, err := observer.ResolveAuthority(ctx, "writer")
	if err != nil {
		t.Fatal(err)
	}
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}
	op := TransportOperation{OperationID: "append-failure", Method: "GET", Service: "git-upload-pack", Repository: "local/repo", RequestPath: "/git/local/repo.git/info/refs", RequestedRefs: []string{}, RefUpdates: []any{}, Authority: authority}
	if err := observer.Received(ctx, &op); err == nil {
		t.Fatal("append failure was accepted")
	}
}

func seedTransportLease(t *testing.T, store *AuthorityWorkerStore, profile, worker, binding string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := store.db.Exec(`INSERT INTO authority_workers(worker_id,profile,profile_version,policy_digest,image_reference,generation,state,capacity,created_at,updated_at,worker_storage_lineage_id,worker_fence_epoch) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, worker, profile, "profile-v1", "policy-digest", "example@sha256:111", 1, "ready", 1, now, now, "storage-"+worker, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO authority_session_leases(principal,profile,idempotency_digest,request_fingerprint,binding_digest,worker_id,created_at,released_at,session_lineage_id) VALUES(?,?,?,?,?,?,?,?,?)`, "broker-principal", profile, "idempotency-"+binding, "request-"+binding, binding, worker, now, "", "session-"+binding); err != nil {
		t.Fatal(err)
	}
}
