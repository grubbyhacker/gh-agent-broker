// Package repositorybackend exposes one fixed bare Git repository over smart HTTP.
package repositorybackend

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Config struct{ RepositoryPath, RepositoryName string }

func (c Config) Validate() error {
	if !filepath.IsAbs(c.RepositoryPath) {
		return fmt.Errorf("repository path must be absolute")
	}
	if strings.TrimSpace(c.RepositoryName) == "" || strings.Contains(c.RepositoryName, "/") {
		return fmt.Errorf("repository name must be a single path segment")
	}
	return nil
}

func New(cfg Config) (http.Handler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return handler{cfg}, nil
}

type handler struct{ cfg Config }

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok\n")); err != nil {
			return
		}
		return
	}
	base := "/" + h.cfg.RepositoryName + ".git"
	valid := (r.Method == http.MethodGet && r.URL.Path == base+"/info/refs" && (r.URL.Query().Get("service") == "git-upload-pack" || r.URL.Query().Get("service") == "git-receive-pack")) || (r.Method == http.MethodPost && (r.URL.Path == base+"/git-upload-pack" || r.URL.Path == base+"/git-receive-pack"))
	if !valid {
		http.NotFound(w, r)
		return
	}
	cmd := exec.CommandContext(r.Context(), "git", "http-backend") // #nosec G204 -- fixed executable and fixed repository configuration.
	cmd.Env = append(os.Environ(), "GIT_PROJECT_ROOT="+filepath.Dir(h.cfg.RepositoryPath), "GIT_HTTP_EXPORT_ALL=1", "REQUEST_METHOD="+r.Method, "PATH_INFO="+r.URL.Path, "QUERY_STRING="+r.URL.RawQuery, "CONTENT_TYPE="+r.Header.Get("Content-Type"), fmt.Sprintf("CONTENT_LENGTH=%d", r.ContentLength), "REMOTE_USER=")
	cmd.Stdin = r.Body
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		http.Error(w, "git backend failed", http.StatusBadGateway)
		return
	}
	head, body, ok := bytes.Cut(out.Bytes(), []byte("\r\n\r\n"))
	if !ok {
		head, body, ok = bytes.Cut(out.Bytes(), []byte("\n\n"))
		if !ok {
			http.Error(w, "invalid git backend response", http.StatusBadGateway)
			return
		}
	}
	for _, line := range strings.Split(string(head), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if found {
			w.Header().Add(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}
	if _, err := io.Copy(w, bytes.NewReader(body)); err != nil {
		return
	}
}
