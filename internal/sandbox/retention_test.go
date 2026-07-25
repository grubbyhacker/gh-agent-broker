package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneRunsDeletesOldTerminalRunsAndSkipsActive(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))

	now := time.Now().UTC()
	writePruneRunMetadata(t, cfg, "run-old-1", StatusStopped, now.Add(-5*time.Hour), now.Add(-5*time.Hour), nil)
	writePruneRunMetadata(t, cfg, "run-old-2", StatusStopped, now.Add(-6*time.Hour), now.Add(-6*time.Hour), nil)
	writePruneRunMetadata(t, cfg, "run-new", StatusStopped, now.Add(-30*time.Minute), now.Add(-30*time.Minute), nil)
	writePruneRunMetadata(t, cfg, "run-running", StatusRunning, now.Add(-6*time.Hour), time.Time{}, nil)

	writeRunMarker(t, cfg, "run-old-1", "keep-me", "one")
	writeRunMarker(t, cfg, "run-old-2", "keep-me", "two")
	writeRunMarker(t, cfg, "run-new", "keep-me", "three")
	writeRunMarker(t, cfg, "run-running", "keep-me", "four")

	report, err := service.PruneRuns(context.Background(), RetentionPolicy{
		MaxAge:     2 * time.Hour,
		KeepNewest: 1,
	})
	if err != nil {
		t.Fatalf("PruneRuns() error = %v", err)
	}
	if report.Deleted != 2 {
		t.Fatalf("deleted = %d, want %d", report.Deleted, 2)
	}
	if report.Skipped != 0 {
		t.Fatalf("skipped = %d, want 0", report.Skipped)
	}
	for _, runID := range []string{"run-old-1", "run-old-2"} {
		if _, err := os.Stat(filepath.Join(cfg.RunsDir, runID)); !os.IsNotExist(err) {
			t.Fatalf("run dir %s should be removed, err=%v", runID, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.RunsDir, "run-running")); err != nil {
		t.Fatalf("run-running should remain: %v", err)
	}
}

func TestPruneRunsUsesMaxBytesBudgetAndPreservesNewest(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))

	now := time.Now().UTC()
	writePruneRunMetadata(t, cfg, "run-oldest", StatusStopped, now.Add(-36*time.Hour), now.Add(-36*time.Hour), nil)
	writePruneRunMetadata(t, cfg, "run-mid", StatusStopped, now.Add(-24*time.Hour), now.Add(-24*time.Hour), map[string][]byte{"artifact.txt": []byte("size-two")})
	writePruneRunMetadata(t, cfg, "run-newest", StatusStopped, now.Add(-18*time.Hour), now.Add(-18*time.Hour), map[string][]byte{
		"artifact.txt": []byte("size-three"),
	})

	writeRunMarker(t, cfg, "run-oldest", "artifact.bin", make([]byte, 2048))
	writeRunMarker(t, cfg, "run-mid", "artifact.bin", make([]byte, 1024))
	writeRunMarker(t, cfg, "run-newest", "artifact.bin", make([]byte, 256))

	oldestSize, err := runDirSizeBytes(filepath.Join(cfg.RunsDir, "run-oldest"))
	if err != nil {
		t.Fatalf("runDirSizeBytes() = %v", err)
	}
	midSize, err := runDirSizeBytes(filepath.Join(cfg.RunsDir, "run-mid"))
	if err != nil {
		t.Fatalf("runDirSizeBytes() = %v", err)
	}
	newestSize, err := runDirSizeBytes(filepath.Join(cfg.RunsDir, "run-newest"))
	if err != nil {
		t.Fatalf("runDirSizeBytes() = %v", err)
	}

	report, err := service.PruneRuns(context.Background(), RetentionPolicy{
		MaxAge:     12 * time.Hour,
		KeepNewest: 1,
		MaxBytes:   midSize + newestSize - 1,
	})
	if err != nil {
		t.Fatalf("PruneRuns() error = %v", err)
	}
	if report.Deleted != 1 {
		t.Fatalf("deleted = %d, want %d", report.Deleted, 1)
	}
	if _, err := os.Stat(filepath.Join(cfg.RunsDir, "run-mid")); err != nil {
		t.Fatalf("run-mid should remain after budget prune: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.RunsDir, "run-newest")); err != nil {
		t.Fatalf("run-newest should remain after budget prune: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.RunsDir, "run-oldest")); !os.IsNotExist(err) {
		t.Fatalf("run-oldest should be removed by budget prune, err=%v", err)
	}
	if report.BudgetBefore < oldestSize+midSize {
		t.Fatalf("budget before = %d, want >= %d", report.BudgetBefore, oldestSize+midSize)
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
	if report.Deleted != 1 {
		t.Fatalf("deleted = %d, want 1", report.Deleted)
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
