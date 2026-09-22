package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gh-agent-broker/internal/capability"
	"gh-agent-broker/internal/release"
)

const (
	testConfiguredImage = "example.com/worker@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testResolvedRef     = "example.com/worker@sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testResolvedDigest  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// fakeResolver is a launch-path ReleaseResolver whose answer is fixed per test.
type fakeResolver struct {
	release ResolvedRelease
	err     error
	calls   int
	seen    []string
}

func (f *fakeResolver) Resolve(_ context.Context, agentType string) (ResolvedRelease, error) {
	f.calls++
	f.seen = append(f.seen, agentType)
	if f.err != nil {
		return ResolvedRelease{}, f.err
	}
	return f.release, nil
}

// releaseTestConfig extends baseTestConfig with an AgentType-backed template and
// release_store_path. The static image is deliberately empty: launch must resolve
// the active release and must never retain a fallback image.
func releaseTestConfig(t *testing.T, agentType string) Config {
	t.Helper()
	cfg := baseTestConfig(t)
	cfg.ReleaseStore = filepath.Join(t.TempDir(), "releases.sqlite")
	tmpl := cfg.Templates["worker"]
	tmpl.AgentType = agentType
	tmpl.Image = ""
	cfg.Templates["worker"] = tmpl
	return cfg
}

func launchWorker(ctx context.Context, t *testing.T, service *Service) LaunchAgentOutput {
	t.Helper()
	out, err := service.LaunchAgent(ctx, LaunchAgentInput{
		Template:   "worker",
		Task:       "make the change",
		Repo:       "owner/repo",
		BaseBranch: "main",
	})
	if err != nil {
		t.Fatalf("LaunchAgent() error = %v", err)
	}
	return out
}

// newTestCapabilityStore opens a real capability store for launch-path tests and
// wires it into the service as the minter, so an AgentType-backed launch mints a
// per-run capability instead of failing closed on a missing store.
func newTestCapabilityStore(t *testing.T, service *Service) *capability.Store {
	t.Helper()
	store, err := capability.OpenStore(context.Background(), filepath.Join(t.TempDir(), "capability.sqlite"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("close capability store: %v", cerr)
		}
	})
	service.SetCapabilityMinter(store)
	return store
}

func lookupTestRun(t *testing.T, service *Service, runID string) RunMetadata {
	t.Helper()
	meta, err := service.lookupRun(runID)
	if err != nil {
		t.Fatalf("lookupRun(%q) error = %v", runID, err)
	}
	return meta
}

// A template without agent_type must behave exactly as before: the configured
// image is used and the resolver is never consulted.
func TestLaunchWithoutAgentTypeUsesConfiguredImage(t *testing.T) {
	cfg := baseTestConfig(t)
	auditLog := testAudit(t)
	defer closeTestAudit(t, auditLog)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, auditLog)
	resolver := &fakeResolver{release: ResolvedRelease{Generation: 9, ImageReference: testResolvedRef, ImageDigest: testResolvedDigest}}
	service.SetReleaseResolver(resolver)

	out := launchWorker(context.Background(), t, service)

	if resolver.calls != 0 {
		t.Fatalf("resolver was consulted %d times for a template without agent_type", resolver.calls)
	}
	if spec := runtime.lastSpec(); spec.Image != testConfiguredImage {
		t.Fatalf("runtime image = %q, want configured image %q", spec.Image, testConfiguredImage)
	}
	meta := lookupTestRun(t, service, out.RunID)
	if meta.Image != testConfiguredImage {
		t.Fatalf("recorded image = %q, want configured image %q", meta.Image, testConfiguredImage)
	}
	if meta.ResolvedReleaseGeneration != 0 {
		t.Fatalf("recorded resolved generation = %d, want 0 for a template without agent_type", meta.ResolvedReleaseGeneration)
	}
}

// A template with agent_type must launch the registry's active, digest-pinned
// reference, and record the resolved generation and digest.
func TestLaunchWithAgentTypeUsesResolvedReference(t *testing.T) {
	cfg := releaseTestConfig(t, "coder")
	auditLog := testAudit(t)
	defer closeTestAudit(t, auditLog)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, auditLog)
	resolver := &fakeResolver{release: ResolvedRelease{Generation: 42, ImageReference: testResolvedRef, ImageDigest: testResolvedDigest}}
	service.SetReleaseResolver(resolver)

	out := launchWorker(context.Background(), t, service)

	if resolver.calls != 1 || len(resolver.seen) != 1 || resolver.seen[0] != "coder" {
		t.Fatalf("resolver calls = %d seen = %v, want one call for agent type %q", resolver.calls, resolver.seen, "coder")
	}
	if spec := runtime.lastSpec(); spec.Image != testResolvedRef {
		t.Fatalf("runtime image = %q, want resolved reference %q", spec.Image, testResolvedRef)
	}
	meta := lookupTestRun(t, service, out.RunID)
	if meta.Image != testResolvedRef {
		t.Fatalf("recorded image = %q, want resolved reference %q", meta.Image, testResolvedRef)
	}
	if meta.ResolvedReleaseGeneration != 42 {
		t.Fatalf("recorded resolved generation = %d, want 42", meta.ResolvedReleaseGeneration)
	}
	// The runtime reports the container's actual image digest, which must be the
	// resolved reference's image (the fake reports spec.Image).
	if meta.ImageDigest != testResolvedRef {
		t.Fatalf("recorded image digest = %q, want the resolved image %q", meta.ImageDigest, testResolvedRef)
	}
}

// agent_type set without release_store_path is a config-load error: the design
// refuses the ambiguity rather than silently falling back to the configured image.
func TestConfigValidateRejectsAgentTypeWithoutReleaseStore(t *testing.T) {
	cfg := baseTestConfig(t)
	tmpl := cfg.Templates["worker"]
	tmpl.AgentType = "coder"
	cfg.Templates["worker"] = tmpl
	// release_store_path deliberately left unset.
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "release_store_path is not configured") {
		t.Fatalf("Validate() error = %v, want release_store_path requirement", err)
	}

	// With release_store_path set, a legacy AgentType template (no capability
	// policy, minting opt-out) validates.
	cfg.ReleaseStore = "/srv/releases.sqlite"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with release_store_path set error = %v", err)
	}
}

func TestConfigValidateAgentTypeReplacesStaticImageRequirement(t *testing.T) {
	cfg := releaseTestConfig(t, "coder")
	cfg.Production = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() AgentType-only production template error = %v", err)
	}

	legacy := baseTestConfig(t)
	tmpl := legacy.Templates["worker"]
	tmpl.Image = ""
	legacy.Templates["worker"] = tmpl
	if err := legacy.Validate(); err == nil || !strings.Contains(err.Error(), "image is required when agent_type is not set") {
		t.Fatalf("Validate() static template error = %v, want image requirement", err)
	}
}

// A malformed agent_type is a config-load error.
func TestConfigValidateRejectsMalformedAgentType(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.ReleaseStore = "/srv/releases.sqlite"
	tmpl := cfg.Templates["worker"]
	tmpl.AgentType = "Coder_01"
	cfg.Templates["worker"] = tmpl
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be kebab-case") {
		t.Fatalf("Validate() error = %v, want kebab-case requirement", err)
	}
}

// An active release whose image is not locally available must REFUSE the launch
// and must NOT fall back to the configured tmpl.Image.
func TestLaunchRefusesWhenActiveReleaseUnavailable(t *testing.T) {
	cfg := releaseTestConfig(t, "coder")
	auditLog := testAudit(t)
	defer closeTestAudit(t, auditLog)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, auditLog)
	service.SetReleaseResolver(&fakeResolver{err: release.ErrUnavailable})

	_, err := service.LaunchAgent(context.Background(), LaunchAgentInput{
		Template: "worker", Task: "make the change", Repo: "owner/repo", BaseBranch: "main",
	})
	if err == nil {
		t.Fatalf("LaunchAgent() error = nil, want refusal on unavailable release")
	}
	if !errors.Is(err, release.ErrUnavailable) {
		t.Fatalf("LaunchAgent() error = %v, want wrapped release.ErrUnavailable", err)
	}
	if spec := runtime.lastSpec(); spec.RunID != "" {
		t.Fatalf("runtime created a container %q; a refused launch must not create one (no fallback image)", spec.RunID)
	}
}

// No active release for the type must REFUSE the launch.
func TestLaunchRefusesWhenNoActiveRelease(t *testing.T) {
	cfg := releaseTestConfig(t, "coder")
	auditLog := testAudit(t)
	defer closeTestAudit(t, auditLog)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, auditLog)
	service.SetReleaseResolver(&fakeResolver{err: release.ErrNoActiveRelease})

	_, err := service.LaunchAgent(context.Background(), LaunchAgentInput{
		Template: "worker", Task: "make the change", Repo: "owner/repo", BaseBranch: "main",
	})
	if err == nil {
		t.Fatalf("LaunchAgent() error = nil, want refusal when no active release")
	}
	if !errors.Is(err, release.ErrNoActiveRelease) {
		t.Fatalf("LaunchAgent() error = %v, want wrapped release.ErrNoActiveRelease", err)
	}
	if spec := runtime.lastSpec(); spec.RunID != "" {
		t.Fatalf("runtime created a container %q; a refused launch must not create one", spec.RunID)
	}
}

// A template that declares an agent_type but has no resolver configured must
// also fail closed at launch (belt-and-braces with the config-load guard).
func TestLaunchRefusesWhenAgentTypeSetButNoResolver(t *testing.T) {
	cfg := releaseTestConfig(t, "coder")
	auditLog := testAudit(t)
	defer closeTestAudit(t, auditLog)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, auditLog)
	// Deliberately do NOT set a resolver.

	_, err := service.LaunchAgent(context.Background(), LaunchAgentInput{
		Template: "worker", Task: "make the change", Repo: "owner/repo", BaseBranch: "main",
	})
	if err == nil || !strings.Contains(err.Error(), "no release registry is configured") {
		t.Fatalf("LaunchAgent() error = %v, want refusal for missing resolver", err)
	}
	if spec := runtime.lastSpec(); spec.RunID != "" {
		t.Fatalf("runtime created a container %q; a refused launch must not create one", spec.RunID)
	}
}

// The resolved generation must be recorded in the run record on disk and
// surfaced in the terminal result, so a run is traceable to the exact release
// that produced it.
func TestResolvedGenerationInRunRecordAndTerminalResult(t *testing.T) {
	cfg := releaseTestConfig(t, "coder")
	auditLog := testAudit(t)
	defer closeTestAudit(t, auditLog)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, auditLog)
	service.SetReleaseResolver(&fakeResolver{release: ResolvedRelease{Generation: 7, ImageReference: testResolvedRef, ImageDigest: testResolvedDigest}})

	out := launchWorker(context.Background(), t, service)

	// Run record on disk.
	//nolint:gosec // G304: test reads generated metadata under this test's temp run directory.
	b, err := os.ReadFile(filepath.Join(cfg.RunsDir, out.RunID, "metadata.json"))
	if err != nil {
		t.Fatalf("read metadata.json: %v", err)
	}
	var meta RunMetadata
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatalf("decode metadata.json: %v", err)
	}
	if meta.ResolvedReleaseGeneration != 7 {
		t.Fatalf("run record resolved generation = %d, want 7", meta.ResolvedReleaseGeneration)
	}

	// Drive the run to a successful terminal state and read the projected result.
	outputDir := filepath.Join(cfg.RunsDir, out.RunID, "output")
	writeTerminalOutputs(t, outputDir, out.RunID)
	runtime.finish(out.RunID, 0, "")
	waitForMetadataStatus(t, cfg, out.RunID, StatusCompleted)

	result, err := service.GetTerminalResult(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatalf("GetTerminalResult() error = %v", err)
	}
	if result.ResolvedReleaseGeneration != 7 {
		t.Fatalf("terminal result resolved generation = %d, want 7", result.ResolvedReleaseGeneration)
	}
}

func writeTerminalOutputs(t *testing.T, outputDir, runID string) {
	t.Helper()
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	result := `{"version":"repository-task-worker-result/v1","outcome":"no_change_required","run_id":"` + runID +
		`","repository":"owner/repo","base_branch":"main","verification":{"status":"not_run"}}`
	if err := os.WriteFile(filepath.Join(outputDir, "result.json"), []byte(result), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "final-summary.md"), []byte("done"), 0o600); err != nil {
		t.Fatal(err)
	}
}
