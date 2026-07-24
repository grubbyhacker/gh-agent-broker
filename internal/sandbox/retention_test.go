package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneRunsDeletesOldTerminalRunsAndSkipsActive(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))

	now := time.Now().UTC()
	writePruneRunMetadata(t, cfg, "run-old", StatusStopped, now.Add(-25*time.Hour), now.Add(-25*time.Hour), nil)
	writeTerminalRuns(t, cfg, 20, now.Add(-20*time.Hour), time.Hour)
	writePruneRunMetadata(t, cfg, "run-running", StatusRunning, now.Add(-6*time.Hour), time.Time{}, nil)

	writeRunMarker(t, cfg, "run-old", "keep-me", "one")
	writeRunMarker(t, cfg, "run-running", "keep-me", "four")

	report, err := service.PruneRuns(context.Background(), RetentionPolicy{
		MaxAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("PruneRuns() error = %v", err)
	}
	if report.Deleted != 1 {
		t.Fatalf("deleted = %d, want 1", report.Deleted)
	}
	if report.Skipped != 0 {
		t.Fatalf("skipped = %d, want 0", report.Skipped)
	}
	for _, runID := range []string{"run-old"} {
		if _, err := os.Stat(filepath.Join(cfg.RunsDir, runID)); !os.IsNotExist(err) {
			t.Fatalf("run dir %s should be removed, err=%v", runID, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.RunsDir, "run-running")); err != nil {
		t.Fatalf("run-running should remain: %v", err)
	}
}

func TestPruneRunsDeletesYoungTerminalRunWhenOverBudget(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))

	now := time.Now().UTC()
	writePruneRunMetadata(t, cfg, "run-young-oldest", StatusStopped, now.Add(-2*time.Hour), now.Add(-2*time.Hour), nil)
	writeRunMarker(t, cfg, "run-young-oldest", "artifact.bin", make([]byte, 1024))
	writeTerminalRuns(t, cfg, 20, now.Add(-90*time.Minute), time.Minute)
	protectedSize, err := runDirSizeBytes(filepath.Join(cfg.RunsDir, "run-00"))
	if err != nil {
		t.Fatalf("runDirSizeBytes() = %v", err)
	}

	report, err := service.PruneRuns(context.Background(), RetentionPolicy{
		MaxAge:   24 * time.Hour,
		MaxBytes: protectedSize * 20,
	})
	if err != nil {
		t.Fatalf("PruneRuns() error = %v", err)
	}
	if report.Deleted != 1 {
		t.Fatalf("deleted = %d, want %d", report.Deleted, 1)
	}
	if _, err := os.Stat(filepath.Join(cfg.RunsDir, "run-young-oldest")); !os.IsNotExist(err) {
		t.Fatalf("young terminal run should be removed by budget prune, err=%v", err)
	}
	if report.BudgetBefore <= report.Policy.MaxBytes {
		t.Fatalf("budget before = %d, want > %d", report.BudgetBefore, report.Policy.MaxBytes)
	}
}

func TestPruneRunsProtectsNewestTwentyTerminalRuns(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	now := time.Now().UTC()
	writeTerminalRuns(t, cfg, 22, now.Add(-2*time.Hour), time.Minute)

	report, err := service.PruneRuns(context.Background(), RetentionPolicy{MaxAge: 24 * time.Hour, MaxBytes: 1})
	if err != nil {
		t.Fatalf("PruneRuns() error = %v", err)
	}
	if report.Deleted != 2 {
		t.Fatalf("deleted = %d, want 2", report.Deleted)
	}
	for i := 2; i < 22; i++ {
		runID := fmt.Sprintf("run-%02d", i)
		if _, err := os.Stat(filepath.Join(cfg.RunsDir, runID)); err != nil {
			t.Fatalf("newest protected run %s should remain: %v", runID, err)
		}
	}
}

func TestPruneRunsLeavesActiveRunsUntouchedWhenTerminalOnly(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	now := time.Now().UTC()
	writeTerminalRuns(t, cfg, 21, now.Add(-2*time.Hour), time.Minute)
	writePruneRunMetadata(t, cfg, "run-pending", StatusPending, now.Add(-48*time.Hour), time.Time{}, nil)
	writePruneRunMetadata(t, cfg, "run-running", StatusRunning, now.Add(-48*time.Hour), time.Time{}, nil)

	_, err := service.PruneRuns(context.Background(), RetentionPolicy{MaxAge: 24 * time.Hour, TerminalOnly: true, MaxBytes: 1})
	if err != nil {
		t.Fatalf("PruneRuns() error = %v", err)
	}
	for _, runID := range []string{"run-pending", "run-running"} {
		if _, err := os.Stat(filepath.Join(cfg.RunsDir, runID)); err != nil {
			t.Fatalf("active run %s should remain: %v", runID, err)
		}
	}
}

func TestPruneRunsDryRunDoesNotDelete(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))

	now := time.Now().UTC()
	runID := "run-delete-me"
	writePruneRunMetadata(t, cfg, runID, StatusStopped, now.Add(-3*time.Hour), now.Add(-3*time.Hour), nil)
	report, err := service.PruneRuns(context.Background(), RetentionPolicy{
		MaxAge: time.Hour,
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("PruneRuns() error = %v", err)
	}
	if report.Deleted != 0 {
		t.Fatalf("deleted = %d, want 0", report.Deleted)
	}
	if _, err := os.Stat(filepath.Join(cfg.RunsDir, runID)); err != nil {
		t.Fatalf("dry-run should not delete run dir: %v", err)
	}
}

func TestPruneRunsToleratesCorruptMetadataAndSkips(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))

	runGood := "run-good"
	runBad := "run-bad"
	runInvalid := "bad$run"

	now := time.Now().UTC()
	writePruneRunMetadata(t, cfg, runGood, StatusStopped, now.Add(-5*time.Hour), now.Add(-5*time.Hour), nil)
	writePruneRunMetadata(t, cfg, runBad, StatusStopped, now.Add(-5*time.Hour), now.Add(-5*time.Hour), nil)
	runBadPath := filepath.Join(cfg.RunsDir, runBad, "metadata.json")
	if err := os.WriteFile(runBadPath, []byte("{bad-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.RunsDir, runInvalid), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.RunsDir, runInvalid, "marker"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := service.PruneRuns(context.Background(), RetentionPolicy{
		MaxAge:     time.Hour,
		KeepNewest: 0,
	})
	if err != nil {
		t.Fatalf("PruneRuns() error = %v", err)
	}
	if report.Skipped != 2 {
		t.Fatalf("skipped = %d, want 2", report.Skipped)
	}
	if report.Deleted != 0 {
		t.Fatalf("deleted = %d, want 0", report.Deleted)
	}
}

func writeTerminalRuns(t *testing.T, cfg Config, count int, first time.Time, interval time.Duration) {
	t.Helper()
	for i := 0; i < count; i++ {
		at := first.Add(time.Duration(i) * interval)
		writePruneRunMetadata(t, cfg, fmt.Sprintf("run-%02d", i), StatusStopped, at, at, nil)
	}
}

func writePruneRunMetadata(t *testing.T, cfg Config, runID string, status string, started, ended time.Time, extra map[string][]byte) {
	t.Helper()
	dir := filepath.Join(cfg.RunsDir, runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := RunMetadata{
		RunID:      runID,
		Template:   "worker",
		Repo:       "owner/repo",
		BaseBranch: "main",
		Branch:     "agent/hermes-coder-01/" + runID,
		Task:       "task",
		Status:     status,
		StartedAt:  started,
		EndedAt:    ended,
		Deadline:   time.Now().UTC().Add(time.Hour),
	}
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, content := range extra {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatalf("write marker %q: %v", name, err)
		}
	}
}

func writeRunMarker(t *testing.T, cfg Config, runID, name string, content interface{}) {
	t.Helper()
	var data []byte
	switch v := content.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		t.Fatalf("unsupported marker content type %T", content)
	}
	path := filepath.Join(cfg.RunsDir, runID, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write marker %q: %v", name, err)
	}
}
