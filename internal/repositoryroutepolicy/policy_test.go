package repositoryroutepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCanonicalDigestIgnoresRouteOrder(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.yaml")
	second := filepath.Join(dir, "second.yaml")
	content := "version: repository-route-policy/v1\nroutes:\n  - repository: local/b\n    backend_url: http://backend-b\n    readable_refs: [refs/heads/main, refs/heads/agent/repository-proof/**]\n    writable_refs: [refs/heads/agent/repository-proof/**]\n    fast_forward_only: true\n    no_delete: true\n  - repository: local/a\n    backend_url: http://backend-a\n    readable_refs: [refs/heads/main, refs/heads/agent/repository-proof/**]\n    writable_refs: [refs/heads/agent/repository-proof/**]\n    fast_forward_only: true\n    no_delete: true\n"
	if err := os.WriteFile(first, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("version: repository-route-policy/v1\nroutes:\n  - repository: local/a\n    backend_url: http://backend-a\n    readable_refs: [refs/heads/main, refs/heads/agent/repository-proof/**]\n    writable_refs: [refs/heads/agent/repository-proof/**]\n    fast_forward_only: true\n    no_delete: true\n  - repository: local/b\n    backend_url: http://backend-b\n    readable_refs: [refs/heads/main, refs/heads/agent/repository-proof/**]\n    writable_refs: [refs/heads/agent/repository-proof/**]\n    fast_forward_only: true\n    no_delete: true\n"), 0o600); err != nil {
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

func TestLoadFailsClosedForUnknownAndUnsafeRouteFields(t *testing.T) {
	dir := t.TempDir()
	for _, content := range []string{
		"version: repository-route-policy/v1\nroutes:\n- repository: local/a\n  backend_url: http://user:pass@backend\n  readable_refs: [refs/heads/main, refs/heads/agent/repository-proof/**]\n  writable_refs: [refs/heads/agent/repository-proof/**]\n  fast_forward_only: true\n  no_delete: true\n",
		"version: repository-route-policy/v1\nroutes:\n- repository: local/a\n  backend_url: http://backend/path?x=y\n  readable_refs: [refs/heads/main, refs/heads/agent/repository-proof/**]\n  writable_refs: [refs/heads/agent/repository-proof/**]\n  fast_forward_only: true\n  no_delete: true\n",
		"version: repository-route-policy/v1\nroutes:\n- repository: local/a\n  backend_url: http://backend\n  writable_namespace: refs/heads/agent/repository-proof/\n",
		"version: repository-route-policy/v1\nroutes:\n- repository: local/a\n  backend_url: http://backend\n  readable_refs: [refs/heads/main]\n  writable_refs: [refs/heads/agent/repository-proof/**]\n  fast_forward_only: true\n  no_delete: true\n",
	} {
		path := filepath.Join(dir, "policy.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("Load unexpectedly accepted %q", content)
		}
	}
}

func TestLoadRejectsSecondYAMLDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	content := "version: repository-route-policy/v1\nroutes:\n- repository: local/a\n  backend_url: http://backend\n  readable_refs: [refs/heads/main, refs/heads/agent/repository-proof/**]\n  writable_refs: [refs/heads/agent/repository-proof/**]\n  fast_forward_only: true\n  no_delete: true\n---\nroutes:\n- repository: local/a\n  backend_url: http://attacker\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted a second YAML document")
	}
}

func TestDigestChangesForEveryContractField(t *testing.T) {
	dir := t.TempDir()
	base := "version: repository-route-policy/v1\nroutes:\n- repository: local/a\n  backend_url: http://backend\n  readable_refs: [refs/heads/main, refs/heads/agent/repository-proof/**]\n  writable_refs: [refs/heads/agent/repository-proof/**]\n  fast_forward_only: true\n  no_delete: true\n"
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(base, "http://backend", "https://backend", 1)
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	q, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Digest == q.Digest {
		t.Fatal("backend authority change did not alter digest")
	}
}
