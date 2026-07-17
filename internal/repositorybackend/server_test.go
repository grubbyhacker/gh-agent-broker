package repositorybackend

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOnlyHealthAndSmartHTTPShapesAreAccepted(t *testing.T) {
	h, err := New(Config{RepositoryPath: "/tmp/repository-proof.git", RepositoryName: "repository-proof"})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/", "/repository-proof.git/HEAD", "/other.git/info/refs?service=git-upload-pack", "/repository-proof.git/info/refs?service=other"} {
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
