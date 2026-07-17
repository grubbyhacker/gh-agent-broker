package pushtripwire

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
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
	req := decodeGolden[ResponseRequest](t, "response-request.json")
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	roundTripGolden(t, req)
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

func TestGoldenMaterialRequest(t *testing.T) {
	req := decodeGolden[MaterialRequest](t, "material-request.json")
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	roundTripGolden(t, req)
}

func TestGoldenMaterialResponse(t *testing.T) {
	out := decodeGolden[MaterialResponse](t, "material-response.json")
	if out.Version != Version || !out.Complete || out.ReasonCode != "" || out.Bounds.CommitCount != len(out.Commits) || out.Bounds.PathCount != len(out.Files) {
		t.Fatalf("invalid complete material response: %+v", out)
	}
	var total int64
	for _, commit := range out.Commits {
		if !shaPattern.MatchString(commit.SHA) {
			t.Fatalf("invalid commit SHA: %q", commit.SHA)
		}
		total += int64(len(commit.Message))
	}
	for _, file := range out.Files {
		if !shaPattern.MatchString(file.CommitSHA) || !shaPattern.MatchString(file.BlobSHA) || file.Path == "" || file.Side != "after" || file.Status != "added" {
			t.Fatalf("invalid file material: %+v", file)
		}
		decoded, err := base64.StdEncoding.DecodeString(file.ContentBase64)
		if err != nil || int64(len(decoded)) != file.Size {
			t.Fatalf("file size/content mismatch: %+v err=%v", file, err)
		}
		total += file.Size
	}
	if total != out.Bounds.TotalBytes {
		t.Fatalf("total bytes = %d, bounds = %d", total, out.Bounds.TotalBytes)
	}
	roundTripGolden(t, out)
}

func TestGoldenResponseResult(t *testing.T) {
	out := decodeGolden[ResponseResult](t, "response-result.json")
	if out.Version != Version || !idPattern.MatchString(out.FindingID) || out.IdempotentReplay || len(out.Actions) != 2 {
		t.Fatalf("invalid response result: %+v", out)
	}
	wantStates := map[string]string{"halt_issuance": "halted", "fence_worker_session": "fence_requested"}
	for _, action := range out.Actions {
		if wantStates[action.Action] != action.State {
			t.Fatalf("invalid action state: %+v", action)
		}
		if _, err := time.Parse(time.RFC3339Nano, action.CompletedAt); err != nil {
			t.Fatalf("invalid completed_at: %q: %v", action.CompletedAt, err)
		}
	}
	roundTripGolden(t, out)
}

func decodeGolden[T any](t *testing.T, name string) T {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "push-tripwire", name)
	// #nosec G304 -- fixture names are fixed constants supplied by these tests.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("strict decode %s: %v", name, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("%s contains trailing JSON", name)
	}
	return out
}

func roundTripGolden[T any](t *testing.T, original T) {
	t.Helper()
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var roundTripped T
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&roundTripped); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, roundTripped) {
		t.Fatalf("round-trip mismatch:\noriginal: %#v\nround-trip: %#v", original, roundTripped)
	}
}
