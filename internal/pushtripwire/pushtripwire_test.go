package pushtripwire

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordingFence struct{ calls int }

func (f *recordingFence) Fence(context.Context, Binding, string) error { f.calls++; return nil }

type transientFence struct{ calls int }

func (f *transientFence) Fence(context.Context, Binding, string) error {
	f.calls++
	if f.calls == 1 {
		return errors.New("transient")
	}
	return nil
}

func TestResponseIsDurableScopedAndIdempotent(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "tripwire.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	binding := &Binding{WorkerID: "worker-1", SessionLineageID: "session-1", WorkerStorageLineageID: "storage-1", WorkerFenceEpoch: 3}
	req := ResponseRequest{Version: Version, FindingID: "finding-1", Profile: "curator", ProfileGeneration: 7, Binding: binding, Actions: []string{"halt_issuance", "fence_worker_session"}}
	fence := &recordingFence{}
	out, err := store.Apply(context.Background(), "delivery-1", req, fence)
	if err != nil {
		t.Fatal(err)
	}
	if out.Actions[0].State != "halted" || out.Actions[1].State != "fenced" || fence.calls != 1 {
		t.Fatalf("unexpected application: %+v calls=%d", out, fence.calls)
	}
	if err := store.CheckIssuance(context.Background(), "curator", 7); err == nil {
		t.Fatal("halted generation was allowed")
	}
	if err := store.CheckIssuance(context.Background(), "curator", 8); err != nil {
		t.Fatalf("unhalted generation denied: %v", err)
	}
	replay, err := store.Apply(context.Background(), "delivery-1", req, fence)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.IdempotentReplay || fence.calls != 1 {
		t.Fatalf("replay=%+v calls=%d", replay, fence.calls)
	}
	req.ProfileGeneration = 8
	if _, err := store.Apply(context.Background(), "delivery-1", req, fence); err == nil {
		t.Fatal("idempotency mismatch accepted")
	}
}

func TestFenceWithoutAdapterRemainsRequested(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "tripwire.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	req := ResponseRequest{Version: Version, FindingID: "finding-2", Profile: "curator", ProfileGeneration: 7, Binding: &Binding{WorkerID: "worker-1", SessionLineageID: "session-1", WorkerStorageLineageID: "storage-1", WorkerFenceEpoch: 3}, Actions: []string{"fence_worker_session"}}
	out, err := store.Apply(context.Background(), "delivery-2", req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Actions) != 1 || out.Actions[0].State != "fence_requested" {
		t.Fatalf("unexpected state: %+v", out)
	}
}

func TestRequestedFenceRetriesOnExactReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tripwire.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	req := ResponseRequest{Version: Version, FindingID: "finding-3", Profile: "curator", ProfileGeneration: 7, Binding: &Binding{WorkerID: "worker-1", SessionLineageID: "session-1", WorkerStorageLineageID: "storage-1", WorkerFenceEpoch: 3}, Actions: []string{"halt_issuance", "fence_worker_session"}}
	fence := &transientFence{}
	first, err := store.Apply(context.Background(), "delivery-3", req, fence)
	if err != nil {
		t.Fatal(err)
	}
	if first.Actions[1].State != "fence_requested" {
		t.Fatalf("first=%+v", first)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	replay, err := store.Apply(context.Background(), "delivery-3", req, fence)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Actions[1].State != "fenced" || !replay.IdempotentReplay || fence.calls != 2 {
		t.Fatalf("replay=%+v calls=%d", replay, fence.calls)
	}
}

func TestGoldenResponseRequest(t *testing.T) {
	b, err := os.ReadFile("../../testdata/push-tripwire/response-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var req ResponseRequest
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "golden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := store.Apply(context.Background(), "golden-response", req, nil); err != nil {
		t.Fatal(err)
	}
	var persisted []byte
	if err := store.db.QueryRow(`SELECT request FROM responses WHERE idempotency_key=?`, "golden-response").Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	var stored ResponseRequest
	if err := json.Unmarshal(persisted, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.DeliveryID != req.DeliveryID || stored.Binding.LogicalSessionID != req.Binding.LogicalSessionID {
		t.Fatalf("persisted identity mismatch: %+v", stored)
	}
}
