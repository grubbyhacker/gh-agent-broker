package repositoryroutepolicy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCanonicalDigestIgnoresRouteOrder(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.yaml")
	second := filepath.Join(dir, "second.yaml")
	content := "version: repository-route-policy/v1\nroutes:\n  - repository: local/b\n    backend_url: http://backend-b\n    writable_namespace: refs/heads/agent/b/\n  - repository: local/a\n    backend_url: http://backend-a\n    writable_namespace: refs/heads/agent/a/\n"
	if err := os.WriteFile(first, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("version: repository-route-policy/v1\nroutes:\n  - repository: local/a\n    backend_url: http://backend-a\n    writable_namespace: refs/heads/agent/a/\n  - repository: local/b\n    backend_url: http://backend-b\n    writable_namespace: refs/heads/agent/b/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := Load(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(second)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest {
		t.Fatalf("digest differs for equivalent manifests: %s != %s", a.Digest, b.Digest)
	}
}
