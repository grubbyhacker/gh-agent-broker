// Package repositorybackend exposes one fixed bare Git repository over smart HTTP.
package repositorybackend

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

const (
	DefaultRepositoryPath = "/var/lib/repository-backend/repository-agent-lifecycle-fixture.git"
	DefaultRepositoryName = "repository-agent-lifecycle-fixture"
	backendProtocolV1     = "version=1"
)

type Config struct {
	RepositoryPath, RepositoryName string
	ExpectedUID, ExpectedGID       int
	RepositoryMode                 os.FileMode
}

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
	if cfg.RepositoryMode == 0 {
		cfg.RepositoryMode = 0o750
	}
	if cfg.ExpectedUID == 0 {
		cfg.ExpectedUID = os.Getuid()
	}
	if cfg.ExpectedGID == 0 {
		cfg.ExpectedGID = os.Getgid()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return handler{cfg}, nil
}

type handler struct{ cfg Config }

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		if err := h.validateRepository(); err != nil {
			http.Error(w, "repository unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok\n")); err != nil {
			return
		}
		return
	}
	base := "/" + h.cfg.RepositoryName + ".git"
	_, discoveryValid := discoveryService(r)
	valid := (r.Method == http.MethodGet && r.URL.Path == base+"/info/refs" && discoveryValid) || (r.Method == http.MethodPost && r.URL.RawQuery == "" && (r.URL.Path == base+"/git-upload-pack" || r.URL.Path == base+"/git-receive-pack"))
	if !valid {
		http.NotFound(w, r)
		return
	}
	protocol, ok := acceptedProtocol(r.Header.Values("Git-Protocol"))
	if !ok {
		http.Error(w, "unsupported Git-Protocol", http.StatusBadRequest)
		return
	}
	cmd := exec.CommandContext(r.Context(), "git", "http-backend") // #nosec G204 -- fixed executable and fixed repository configuration.
	cmd.Env = append(os.Environ(), "GIT_PROJECT_ROOT="+filepath.Dir(h.cfg.RepositoryPath), "GIT_HTTP_EXPORT_ALL=1", "REQUEST_METHOD="+r.Method, "PATH_INFO="+r.URL.Path, "QUERY_STRING="+r.URL.RawQuery, "CONTENT_TYPE="+r.Header.Get("Content-Type"), fmt.Sprintf("CONTENT_LENGTH=%d", r.ContentLength), "REMOTE_USER=", "GIT_PROTOCOL="+protocol)
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

func discoveryService(r *http.Request) (string, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", false
	}
	if len(query) != 1 || len(query["service"]) != 1 {
		return "", false
	}
	service := query["service"][0]
	return service, service == "git-upload-pack" || service == "git-receive-pack"
}

// acceptedProtocol pins this backend to v0 (no header) and v1. Git protocol v2
// is intentionally rejected: Alpine Git 2.49.1 may otherwise accept hidden SHA wants.
func acceptedProtocol(values []string) (string, bool) {
	if len(values) == 0 {
		return "", true
	}
	return backendProtocolV1, len(values) == 1 && values[0] == backendProtocolV1
}

func (h handler) validateRepository() error {
	root := filepath.Dir(h.cfg.RepositoryPath)
	for _, path := range []string{root, h.cfg.RepositoryPath} {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", path)
		}
		if info.Mode().Perm() != h.cfg.RepositoryMode.Perm() {
			return fmt.Errorf("%s mode is %o", path, info.Mode().Perm())
		}
		// The production image is Linux. Darwin's syscall.Stat_t does not expose
		// the effective group consistently for APFS temporary directories.
		if runtime.GOOS == "linux" {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int(stat.Uid) != h.cfg.ExpectedUID || int(stat.Gid) != h.cfg.ExpectedGID {
				return fmt.Errorf("%s ownership does not match expected %d:%d", path, h.cfg.ExpectedUID, h.cfg.ExpectedGID)
			}
		}
	}
	probe := filepath.Join(h.cfg.RepositoryPath, "HEAD")
	//nolint:gosec // probe is derived from the validated fixed repository path.
	f, err := os.OpenFile(probe, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	return f.Close()
}
