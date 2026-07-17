package repositorybackend

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestOnlyHealthAndSmartHTTPShapesAreAccepted(t *testing.T) {
	dir := t.TempDir()
	//nolint:gosec // health contract intentionally requires the production repository mode.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(dir, "repository-agent-lifecycle-fixture.git")
	//nolint:gosec // health contract intentionally requires the production repository mode.
	if err := os.Mkdir(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // Git's HEAD must be readable by the repository service.
	if err := os.WriteFile(filepath.Join(repo, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{RepositoryPath: repo, RepositoryName: "repository-agent-lifecycle-fixture", ExpectedUID: os.Getuid(), ExpectedGID: os.Getgid(), RepositoryMode: 0o755})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/", "/repository-agent-lifecycle-fixture.git/HEAD", "/other.git/info/refs?service=git-upload-pack", "/repository-agent-lifecycle-fixture.git/info/refs?service=other"} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d", target, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("health: got %d", w.Code)
	}
}

func TestHealthFailsClosedForRepositoryOwnershipAndMode(t *testing.T) {
	dir := t.TempDir()
	//nolint:gosec // health contract intentionally requires the production repository mode.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(dir, "repo.git")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // Git's HEAD must be readable by the repository service.
	if err := os.WriteFile(filepath.Join(repo, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{RepositoryPath: repo, RepositoryName: "repo", ExpectedUID: os.Getuid(), ExpectedGID: os.Getgid(), RepositoryMode: 0o755})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("health status = %d", w.Code)
	}
}

func TestUnsupportedGitProtocolIsRejectedBeforeBackend(t *testing.T) {
	h, err := New(Config{RepositoryPath: "/unused/repo.git", RepositoryName: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"version=2", "version=0", "version=1:agent=x"} {
		r := httptest.NewRequest(http.MethodGet, "/repo.git/info/refs?service=git-upload-pack", nil)
		r.Header.Set("Git-Protocol", protocol)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%q status = %d", protocol, w.Code)
		}
	}
}
