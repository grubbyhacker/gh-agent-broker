package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSlimRunsPreservesDeliverablesAndRemovesReconstructiblePaths(t *testing.T) {
	cfg := baseTestConfig(t)
	runtime := newFakeRuntime()
	runtime.logs = "agent log line\nsecond line"
	service := NewService(cfg, runtime, testAudit(t))
	defer closeTestAudit(t, service.audit)

	runID := "run-terminal"
	now := time.Now().UTC()
	writeSlimRunMetadata(t, cfg, runID, StatusStopped, now.Add(-2*time.Hour), now.Add(-2*time.Hour), "container-"+runID, []string{
		"/output/final-summary.md",
		"/lessons/run-summary.md",
	})

	runDir := filepath.Join(cfg.RunsDir, runID)
	if err := os.MkdirAll(filepath.Join(runDir, "output"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "lessons"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "output", "final-summary.md"), []byte("final summary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "output", "wrapper-diagnostics.json"), []byte("{\"source\":\"worker\"}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "output", "agent-workspace", ".git", "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "output", "agent-workspace", "review.log"), []byte("should be removed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "work", "home", ".cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "work", "home", "huge.bin"), make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "lessons", "run-summary.md"), []byte("lesson summary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "logs", "wrapper.log"), []byte("runtime noise"), 0o600); err != nil {
		t.Fatal(err)
	}

	beforeSize, err := runDirSizeBytes(runDir)
	if err != nil {
		t.Fatalf("runDirSizeBytes() before = %v", err)
	}

	report, err := service.SlimRuns(context.Background(), RetentionPolicy{
		MaxAge: time.Hour,
	})
	if err != nil {
		t.Fatalf("SlimRuns() error = %v", err)
	}
	if got := report.Slimmed; got != 1 {
		t.Fatalf("slimmed = %d, want 1", got)
	}

	if _, err := os.Stat(filepath.Join(runDir, "work")); !os.IsNotExist(err) {
		t.Fatalf("work should be removed, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "output", "agent-workspace")); !os.IsNotExist(err) {
		t.Fatalf("output/agent-workspace should be removed, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "output", "wrapper-diagnostics.json")); err != nil {
		t.Fatalf("wrapper-diagnostics should remain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "output", "final-summary.md")); err != nil {
		t.Fatalf("deliverable final-summary should remain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "lessons", "run-summary.md")); err != nil {
		t.Fatalf("lesson deliverable should remain: %v", err)
	}

	manifestPath := filepath.Join(runDir, "output", slimArtifactsManifest)
	//nolint:gosec // G304: manifestPath is derived from an in-test generated sandbox fixture.
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	var manifest runArtifactManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("manifest unmarshal = %v", err)
	}
	if manifest.RunID != runID {
		t.Fatalf("manifest run_id = %q, want %q", manifest.RunID, runID)
	}
	if len(manifest.OutputFiles) == 0 {
		t.Fatalf("manifest output files should include kept outputs")
	}

	if _, err := os.Stat(filepath.Join(runDir, "logs", slimRunLog)); err != nil {
		t.Fatalf("log snapshot should remain: %v", err)
	}

	afterSize, err := runDirSizeBytes(runDir)
	if err != nil {
		t.Fatalf("runDirSizeBytes() after = %v", err)
	}
	if afterSize >= beforeSize {
		t.Fatalf("expected run size to shrink, before=%d after=%d", beforeSize, afterSize)
	}

	foundWorkRemoval := false
	foundWorkspaceRemoval := false
	if len(report.Entries) == 0 {
		t.Fatalf("expected report entries")
	}
	for _, path := range report.Entries[0].RemovedPaths {
		switch {
		case strings.HasSuffix(path, "work") || strings.HasSuffix(path, "work/home") || strings.HasSuffix(path, "work/home/.cache"):
			foundWorkRemoval = true
		case strings.Contains(path, "agent-workspace"):
			foundWorkspaceRemoval = true
		}
	}
	if !foundWorkRemoval {
		t.Fatalf("removed paths should include work")
	}
	if !foundWorkspaceRemoval {
		t.Fatalf("removed paths should include agent-workspace")
	}
}

func TestSlimRunsDryRunIsNonMutating(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	defer closeTestAudit(t, service.audit)

	runID := "run-dry-run"
	now := time.Now().UTC()
	writeSlimRunMetadata(t, cfg, runID, StatusStopped, now.Add(-2*time.Hour), now.Add(-2*time.Hour), "", []string{"/output/final-summary.md"})

	runDir := filepath.Join(cfg.RunsDir, runID)
	if err := os.MkdirAll(filepath.Join(runDir, "work", "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "output"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "work", "home", "state.bin"), make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "output", "final-summary.md"), []byte("summary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "output", "extra.txt"), []byte("should go"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := service.SlimRuns(context.Background(), RetentionPolicy{
		MaxAge: time.Hour,
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("SlimRuns() error = %v", err)
	}
	if err := assertRunDirHasPath(runDir, "work", "home", "state.bin"); err != nil {
		t.Fatalf("%v", err)
	}
	if err := assertRunDirHasPath(runDir, "output", "extra.txt"); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestSlimRunsSkipsRunningRunByDefault(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	defer closeTestAudit(t, service.audit)

	runID := "run-running"
	now := time.Now().UTC()
	writeSlimRunMetadata(t, cfg, runID, StatusRunning, now.Add(-2*time.Hour), time.Time{}, "", []string{"/output/final-summary.md"})
	runDir := filepath.Join(cfg.RunsDir, runID)
	if err := os.MkdirAll(filepath.Join(runDir, "work", "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "output"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "work", "home", "state.bin"), []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := service.SlimRuns(context.Background(), RetentionPolicy{
		MaxAge: time.Hour,
	})
	if err != nil {
		t.Fatalf("SlimRuns() error = %v", err)
	}
	if got := report.Slimmed; got != 0 {
		t.Fatalf("slimmed = %d, want 0", got)
	}
	if err := assertRunDirHasPath(runDir, "work", "home", "state.bin"); err != nil {
		t.Fatalf("%v", err)
	}
}

func writeSlimRunMetadata(t *testing.T, cfg Config, runID, status string, started, ended time.Time, containerID string, deliverables []string) {
	t.Helper()
	dir := filepath.Join(cfg.RunsDir, runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := RunMetadata{
		RunID:            runID,
		Template:         "worker",
		Repo:             "owner/repo",
		BaseBranch:       "main",
		Branch:           "agent/hermes-coder-01/" + runID,
		Task:             "task",
		Status:           status,
		ContainerID:      containerID,
		Deliverables:     deliverables,
		StartedAt:        started,
		Deadline:         time.Now().UTC().Add(time.Hour),
		EndedAt:          ended,
		WorkerAgentID:    "agent-id",
		CredentialBundle: "codex",
	}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
}

func assertRunDirHasPath(runDir string, parts ...string) error {
	p := filepath.Join(append([]string{runDir}, parts...)...)
	if _, err := os.Stat(p); err != nil {
		return err
	}
	return nil
}
