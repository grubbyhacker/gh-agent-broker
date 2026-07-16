package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDockerAuthorityVolumeInitializerIntegration exercises the real Docker
// capability boundary. It is opt-in because it builds an isolated test image
// and requires a running Docker daemon.
func TestDockerAuthorityVolumeInitializerIntegration(t *testing.T) {
	if os.Getenv("RUN_DOCKER_INTEGRATION") != "1" {
		t.Skip("set RUN_DOCKER_INTEGRATION=1 to run Docker integration tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI is unavailable")
	}
	if err := dockerCommand(context.Background(), "info"); err != nil {
		t.Skipf("Docker daemon is unavailable: %v", err)
	}

	stamp := strings.ReplaceAll(time.Now().UTC().Format("20060102t150405.000000000"), ".", "")
	image := "gh-agent-broker-volume-initializer-test:" + stamp
	volume := "gh-agent-broker-volume-initializer-test-" + stamp
	lineage := "11111111111111111111111111111111"
	contextDir := filepath.Join("..", "..", "testdata", "authority-volume-initializer")
	if err := dockerCommand(context.Background(), "build", "--quiet", "--tag", image, contextDir); err != nil {
		t.Fatalf("build initializer fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := dockerCommand(context.Background(), "image", "rm", "--force", image); err != nil {
			t.Errorf("remove initializer fixture image: %v", err)
		}
	})
	if err := dockerCommand(context.Background(), "volume", "create", volume); err != nil {
		t.Fatalf("create test volume: %v", err)
	}
	t.Cleanup(func() {
		if err := dockerCommand(context.Background(), "volume", "rm", "--force", volume); err != nil {
			t.Errorf("remove initializer test volume: %v", err)
		}
	})

	backend := NewDockerBackend("")
	mounts := []Mount{{Source: volume, Target: agentdControlV1WorkspaceRoot, Volume: true, VolumeSubpath: lineage}}
	if err := backend.ensureAuthorityVolumeSubpaths(context.Background(), image, lineage, mounts, agentdControlV1WorkspaceRoot); err != nil {
		t.Fatalf("initialize authority volume: %v", err)
	}

	assert := "test \"$(stat -c %U:%G:%a /lineage/" + lineage + ")\" = bun:bun:711 && test \"$(stat -c %U:%G:%a /lineage/" + lineage + "/.agentd-state)\" = bun:bun:700"
	if err := dockerCommand(context.Background(), "run", "--rm", "--network", "none", "-v", volume+":/lineage:ro", image, "sh", "-ec", assert); err != nil {
		t.Fatalf("verify private state ownership and modes: %v", err)
	}
	if err := dockerCommand(context.Background(), "run", "--rm", "--network", "none", "--user", "65534:65534", "-v", volume+":/lineage:ro", image, "sh", "-ec", "test -x /lineage/"+lineage); err != nil {
		t.Fatalf("verify lineage root traversal: %v", err)
	}
	for _, name := range []string{"sandbox-authority-volume-init-" + lineage, "sandbox-authority-state-init-" + lineage} {
		output, err := dockerCommandOutput(context.Background(), "ps", "--all", "--quiet", "--filter", "name=^/"+name+"$")
		if err != nil {
			t.Fatalf("list helper %q: %v", name, err)
		}
		if strings.TrimSpace(output) != "" {
			t.Fatalf("initializer helper %q remains after completion: %s", name, output)
		}
	}
}

func dockerCommand(ctx context.Context, args ...string) error {
	//nolint:gosec // Every call site uses fixed Docker subcommands and test-generated image/volume identifiers.
	cmd := exec.CommandContext(ctx, "docker", args...)
	return cmd.Run()
}

func dockerCommandOutput(ctx context.Context, args ...string) (string, error) {
	//nolint:gosec // Every call site uses fixed Docker subcommands and test-generated image/volume identifiers.
	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.Output()
	return string(output), err
}
