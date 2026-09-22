package correlation

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "correlation.sqlite")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return store, path
}

func TestRecordWritesCorrelationAndOutboxAtomically(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()

	id := Identity{AgentID: "hermes-coder-01", OperationID: "op-1", RunID: "run-123"}
	c, err := store.Record(ctx, id, "grubbyhacker/gh-agent-broker", 177)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if c.PRNumber != 177 || c.Repo != "grubbyhacker/gh-agent-broker" {
		t.Fatalf("correlation = %+v", c)
	}

	got, err := store.GetByPR(ctx, "grubbyhacker/gh-agent-broker", 177)
	if err != nil {
		t.Fatalf("GetByPR: %v", err)
	}
	if got.OperationID != "op-1" || got.RunID != "run-123" || got.AgentID != "hermes-coder-01" {
		t.Fatalf("GetByPR = %+v", got)
	}

	pending, err := store.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if pending != 1 {
		t.Fatalf("pending = %d, want 1", pending)
	}
	if err := store.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRecordFailsClosedOnUnboundCall(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()

	cases := []struct {
		name string
		id   Identity
		repo string
		pr   int64
	}{
		{"missing agent", Identity{OperationID: "op"}, "o/r", 1},
		{"missing operation", Identity{AgentID: "a"}, "o/r", 1},
		{"missing repo", Identity{AgentID: "a", OperationID: "op"}, "", 1},
		{"nonpositive pr", Identity{AgentID: "a", OperationID: "op"}, "o/r", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.Record(ctx, tc.id, tc.repo, tc.pr); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
	pending, err := store.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if pending != 0 {
		t.Fatalf("unbound calls wrote %d events, want 0", pending)
	}
}

func TestRecordIsIdempotentOnOperationID(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	id := Identity{AgentID: "a", OperationID: "op-dup", RunID: "run-1"}

	first, err := store.Record(ctx, id, "o/r", 5)
	if err != nil {
		t.Fatalf("first Record: %v", err)
	}
	second, err := store.Record(ctx, id, "o/r", 5)
	if err != nil {
		t.Fatalf("second Record: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("idempotent record produced different ids: %d vs %d", first.ID, second.ID)
	}
	pending, err := store.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if pending != 1 {
		t.Fatalf("replay produced %d events, want exactly 1", pending)
	}
}

func TestClaimAckDrainsOutbox(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	if _, err := store.Record(ctx, Identity{AgentID: "a", OperationID: "op-1"}, "o/r", 1); err != nil {
		t.Fatalf("Record: %v", err)
	}

	claimed, err := store.ClaimPending(ctx, "consumer-1", 10, time.Minute)
	if err != nil {
		t.Fatalf("ClaimPending: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed %d, want 1", len(claimed))
	}
	if claimed[0].Version != OutboxEventVersion {
		t.Fatalf("event version = %q", claimed[0].Version)
	}

	// A second consumer sees nothing while the claim is fresh.
	again, err := store.ClaimPending(ctx, "consumer-2", 10, time.Minute)
	if err != nil {
		t.Fatalf("second ClaimPending: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("fresh claim leaked %d events to a second consumer", len(again))
	}

	if err := store.Ack(ctx, claimed[0].ID, "consumer-1"); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	pending, err := store.PendingCount(ctx)
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if pending != 0 {
		t.Fatalf("after ack pending = %d, want 0", pending)
	}
}

func TestAckRefusesWrongClaimToken(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	if _, err := store.Record(ctx, Identity{AgentID: "a", OperationID: "op-1"}, "o/r", 1); err != nil {
		t.Fatalf("Record: %v", err)
	}
	claimed, err := store.ClaimPending(ctx, "consumer-1", 1, time.Minute)
	if err != nil {
		t.Fatalf("ClaimPending: %v", err)
	}
	if err := store.Ack(ctx, claimed[0].ID, "impostor"); !errors.Is(err, ErrClaimMismatch) {
		t.Fatalf("Ack with wrong token = %v, want ErrClaimMismatch", err)
	}
}

func TestExpiredClaimIsReclaimable(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	if _, err := store.Record(ctx, Identity{AgentID: "a", OperationID: "op-1"}, "o/r", 1); err != nil {
		t.Fatalf("Record: %v", err)
	}
	// Consumer 1 claims, then crashes without acking (simulated by advancing now).
	base := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	if _, err := store.ClaimPending(ctx, "consumer-1", 1, time.Minute); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	// 2 minutes later the claim has expired; consumer 2 reclaims it.
	store.now = func() time.Time { return base.Add(2 * time.Minute) }
	reclaimed, err := store.ClaimPending(ctx, "consumer-2", 1, time.Minute)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if len(reclaimed) != 1 {
		t.Fatalf("reclaimed %d, want 1", len(reclaimed))
	}
	if reclaimed[0].Attempts != 2 {
		t.Fatalf("attempts = %d, want 2 after reclaim", reclaimed[0].Attempts)
	}
	// The original consumer can no longer ack.
	if err := store.Ack(ctx, reclaimed[0].ID, "consumer-1"); !errors.Is(err, ErrClaimMismatch) {
		t.Fatalf("stale consumer ack = %v, want ErrClaimMismatch", err)
	}
}

// TestCrashReplayReopensAndValidates simulates a crash: the store is closed
// abruptly after Record commits, then reopened. The committed correlation and
// its outbox event must both survive and validate, and remain claimable.
func TestCrashReplayReopensAndValidates(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "correlation.sqlite")

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := store.Record(ctx, Identity{AgentID: "a", OperationID: "op-crash", RunID: "run-9"}, "o/r", 42); err != nil {
		t.Fatalf("Record: %v", err)
	}
	// Simulate a crash: drop the handle without draining.
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened store: %v", err)
		}
	})

	if err := reopened.Validate(ctx); err != nil {
		t.Fatalf("Validate after replay: %v", err)
	}
	got, err := reopened.GetByPR(ctx, "o/r", 42)
	if err != nil {
		t.Fatalf("GetByPR after replay: %v", err)
	}
	if got.OperationID != "op-crash" {
		t.Fatalf("survived correlation = %+v", got)
	}
	claimed, err := reopened.ClaimPending(ctx, "consumer-after-crash", 10, time.Minute)
	if err != nil {
		t.Fatalf("ClaimPending after replay: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("crash-surviving event not claimable: got %d", len(claimed))
	}
}

func TestValidateRejectsUnknownVersion(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	c, err := store.Record(ctx, Identity{AgentID: "a", OperationID: "op-1"}, "o/r", 1)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := store.db.ExecContext(ctx,
		`UPDATE outbox_events SET version = ? WHERE correlation_id = ?`, "run-pr-correlation/v99", c.ID); err != nil {
		t.Fatalf("corrupt version: %v", err)
	}
	if err := store.Validate(ctx); err == nil {
		t.Fatal("Validate accepted an unknown event version")
	}
}

func TestOpenRejectsRelativePath(t *testing.T) {
	if _, err := Open(context.Background(), "relative/path.sqlite"); err == nil {
		t.Fatal("Open accepted a relative path")
	}
}
