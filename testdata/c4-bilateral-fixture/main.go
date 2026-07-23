// c4-bilateral-fixture is a test-only local provider and smart-Git backend.
// Its Dockerfile is deliberately outside the product image build.
package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	listenEnv          = "C4_FIXTURE_LISTEN"
	repositoryEnv      = "C4_FIXTURE_REPOSITORY"
	publicKeyEnv       = "C4_FIXTURE_APP_PUBLIC_KEY_PATH"
	issuerEnv          = "C4_FIXTURE_APP_ISSUER"
	fixtureRepoPath    = "/grubbyhacker/repository-worker-lifecycle-test.git"
	fixtureToken       = "c4-fixture-installation-token"
	fixtureTaskPath    = "fixture-task.md"
	fixtureTaskBody    = "status: pending\n"
	backendStderrLimit = 2048
)

func main() {
	repository := strings.TrimSpace(os.Getenv(repositoryEnv))
	if !filepath.IsAbs(repository) {
		log.Fatal("C4_FIXTURE_REPOSITORY must be an absolute bare repository path")
	}
	if err := ensureBareRepository(repository); err != nil {
		log.Fatal(err)
	}
	verifier, err := loadFixtureJWTVerifier()
	if err != nil {
		log.Fatal(err)
	}
	listen := strings.TrimSpace(os.Getenv(listenEnv))
	if listen == "" {
		listen = ":18080"
	}
	server := &http.Server{
		Addr:              listen,
		Handler:           fixtureHandler{repository: repository, verifier: verifier},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
	}
	log.Fatal(server.ListenAndServe())
}

type fixtureHandler struct {
	repository string
	verifier   fixtureJWTVerifier
}

func (h fixtureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens" {
		h.serveInstallationToken(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, fixtureRepoPath) {
		h.serveGit(w, r)
		return
	}
	http.NotFound(w, r)
}

func (h fixtureHandler) serveInstallationToken(w http.ResponseWriter, r *http.Request) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authorization, "Bearer ") || !h.verifier.valid(strings.TrimPrefix(authorization, "Bearer ")) {
		http.Error(w, "installation token authorization required", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"token":"`+fixtureToken+`","expires_at":"2030-01-01T00:00:00Z"}`)
}

func (h fixtureHandler) serveGit(w http.ResponseWriter, r *http.Request) {
	user, password, ok := r.BasicAuth()
	if !ok || user != "x-access-token" || password != fixtureToken {
		w.Header().Set("WWW-Authenticate", `Basic realm="c4-fixture"`)
		http.Error(w, "installation token required", http.StatusUnauthorized)
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path, fixtureRepoPath)
	if !validGitRequest(r.Method, suffix, r.URL.RawQuery) {
		http.NotFound(w, r)
		return
	}
	protocol, validProtocol := acceptedFixtureGitProtocol(r.Header.Values("Git-Protocol"))
	if !validProtocol {
		http.Error(w, "unsupported Git-Protocol", http.StatusBadRequest)
		return
	}
	cmd := exec.CommandContext(r.Context(), "git", "http-backend") // #nosec G204 -- fixed executable and fixed test repository path.
	cmd.Env = append(os.Environ(),
		"GIT_PROJECT_ROOT="+filepath.Dir(h.repository),
		"GIT_HTTP_EXPORT_ALL=1",
		"REQUEST_METHOD="+r.Method,
		"PATH_INFO=/"+filepath.Base(h.repository)+suffix,
		"QUERY_STRING="+r.URL.RawQuery,
		"CONTENT_TYPE="+r.Header.Get("Content-Type"),
		fmt.Sprintf("CONTENT_LENGTH=%d", r.ContentLength),
		"REMOTE_USER=",
		"GIT_PROTOCOL="+protocol,
	)
	cmd.Stdin = r.Body
	var output bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		evidence := boundedBackendStderr(stderr.Bytes())
		log.Printf("c4_git_http_backend stage=git_http_backend_failed reason=%s exit_status=%d stderr=%q stderr_truncated=%t", backendFailureReason(err), backendExitStatus(err), evidence.text, evidence.truncated)
		http.Error(w, "git backend failed", http.StatusBadGateway)
		return
	}
	head, body, found := bytes.Cut(output.Bytes(), []byte("\r\n\r\n"))
	if !found {
		head, body, found = bytes.Cut(output.Bytes(), []byte("\n\n"))
		if !found {
			http.Error(w, "invalid git backend response", http.StatusBadGateway)
			return
		}
	}
	for _, line := range strings.Split(string(head), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok {
			w.Header().Add(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}
	_, _ = io.Copy(w, bytes.NewReader(body))
}

type backendStderrEvidence struct {
	text      string
	truncated bool
}

// boundedBackendStderr keeps only printable, bounded diagnostics. The fixture
// never forwards credentials to git-http-backend, and this additionally removes
// its own fixed test token defensively before evidence is retained.
func boundedBackendStderr(value []byte) backendStderrEvidence {
	truncated := len(value) > backendStderrLimit
	if truncated {
		value = value[:backendStderrLimit]
	}
	var out strings.Builder
	for _, c := range string(value) {
		if c == '\n' || c == '\r' || c == '\t' || (c >= ' ' && c <= '~') {
			out.WriteRune(c)
		} else {
			out.WriteRune('?')
		}
	}
	return backendStderrEvidence{
		text:      strings.ReplaceAll(out.String(), fixtureToken, "[redacted]"),
		truncated: truncated,
	}
}

func backendFailureReason(err error) string {
	if _, ok := err.(*exec.ExitError); ok {
		return "git_http_backend_exit_nonzero"
	}
	return "git_http_backend_start_failed"
}

func backendExitStatus(err error) int {
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode()
	}
	return -1
}

// acceptedFixtureGitProtocol mirrors the protocol header Git itself sends to
// smart HTTP. The disposable C4 backend supports v0, v1, and v2 so the real
// smoke image can negotiate its default v2 advertisement; the broker remains
// an opaque forwarder and is not changed by this fixture-only behavior.
func acceptedFixtureGitProtocol(values []string) (string, bool) {
	if len(values) == 0 {
		return "", true
	}
	if len(values) != 1 {
		return "", false
	}
	protocol := strings.TrimSpace(values[0])
	switch protocol {
	case "version=1", "version=2":
		return protocol, true
	default:
		return "", false
	}
}

func validGitRequest(method, suffix, query string) bool {
	if method == http.MethodGet && suffix == "/info/refs" {
		return query == "service=git-upload-pack" || query == "service=git-receive-pack"
	}
	return method == http.MethodPost && query == "" && (suffix == "/git-upload-pack" || suffix == "/git-receive-pack")
}

func ensureBareRepository(repository string) error {
	if info, err := os.Stat(repository); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("fixture repository %q is not a directory", repository)
		}
		if _, err = os.Stat(filepath.Join(repository, "HEAD")); err == nil {
			return ensureFixtureSeed(repository)
		}
	}
	if err := os.MkdirAll(filepath.Dir(repository), 0o755); err != nil {
		return err
	}
	if _, err := runGit(nil, "init", "--bare", "--initial-branch=main", repository); err != nil {
		return fmt.Errorf("initialize disposable fixture repository: %w", err)
	}
	return ensureFixtureSeed(repository)
}

func ensureFixtureSeed(repository string) error {
	if _, err := runGit(nil, "--git-dir="+repository, "rev-parse", "--verify", "refs/heads/main"); err == nil {
		if err := verifyFixtureMain(repository); err != nil {
			return errors.New("fixture repository main must contain the exact pending fixture-task.md")
		}
		return nil
	}

	blob, err := runGit(strings.NewReader(fixtureTaskBody), "--git-dir="+repository, "hash-object", "-w", "--stdin")
	if err != nil {
		return fmt.Errorf("write pending fixture task: %w", err)
	}
	tree, err := runGit(strings.NewReader("100644 blob "+strings.TrimSpace(string(blob))+"\t"+fixtureTaskPath+"\n"), "--git-dir="+repository, "mktree")
	if err != nil {
		return fmt.Errorf("create fixture tree: %w", err)
	}
	commit, err := runGit(nil, "--git-dir="+repository, "-c", "user.name=C4 Fixture", "-c", "user.email=c4-fixture@example.invalid", "commit-tree", strings.TrimSpace(string(tree)), "-m", "seed pending C4 fixture task")
	if err != nil {
		return fmt.Errorf("commit fixture task: %w", err)
	}
	if _, err := runGit(nil, "--git-dir="+repository, "update-ref", "refs/heads/main", strings.TrimSpace(string(commit))); err != nil {
		return fmt.Errorf("set fixture main: %w", err)
	}
	return nil
}

// verifyFixtureMain keeps the disposable repository deterministic. The C4
// client observes main, so accepting additional tracked paths would silently
// change the fixture contract even when fixture-task.md itself is unchanged.
func verifyFixtureMain(repository string) error {
	tree, err := runGit(nil, "--git-dir="+repository, "ls-tree", "-r", "--full-tree", "main")
	if err != nil || !exactFixtureTree(tree) {
		return errors.New("fixture main tree differs from the exact seed")
	}
	body, err := runGit(nil, "--git-dir="+repository, "show", "main:"+fixtureTaskPath)
	if err != nil || string(body) != fixtureTaskBody {
		return errors.New("fixture task content differs from the exact seed")
	}
	return nil
}

func exactFixtureTree(tree []byte) bool {
	const prefix = "100644 blob "
	const suffix = "\t" + fixtureTaskPath + "\n"
	line := string(tree)
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, suffix) {
		return false
	}
	objectID := strings.TrimSuffix(strings.TrimPrefix(line, prefix), suffix)
	return objectID != "" && !strings.ContainsAny(objectID, "\t\n\r ")
}

func runGit(input io.Reader, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...) // #nosec G204 -- all commands and arguments are fixed fixture operations.
	cmd.Stdin = input
	return cmd.Output()
}

// fixtureJWTVerifier implements the GitHub App JWT acceptance boundary for the
// local provider. GitHub requires RS256 plus iss, iat, and exp; exp may be no
// more than ten minutes ahead. See https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app.
type fixtureJWTVerifier struct {
	publicKey *rsa.PublicKey
	issuer    string
	now       func() time.Time
}

func loadFixtureJWTVerifier() (fixtureJWTVerifier, error) {
	issuer := strings.TrimSpace(os.Getenv(issuerEnv))
	publicKeyPath := strings.TrimSpace(os.Getenv(publicKeyEnv))
	if issuer == "" || publicKeyPath == "" {
		return fixtureJWTVerifier{}, errors.New("fixture App JWT public key path and issuer are required")
	}
	pemBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fixtureJWTVerifier{}, fmt.Errorf("read fixture App JWT public key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fixtureJWTVerifier{}, errors.New("parse fixture App JWT public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return fixtureJWTVerifier{}, errors.New("parse fixture App JWT public key")
		}
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fixtureJWTVerifier{}, errors.New("fixture App JWT public key must be RSA")
	}
	return fixtureJWTVerifier{publicKey: rsaKey, issuer: issuer, now: time.Now}, nil
}

func (v fixtureJWTVerifier) valid(compact string) bool {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header struct {
		Algorithm string `json:"alg"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Algorithm != "RS256" {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	decoder.UseNumber()
	var claims struct {
		Issuer   string      `json:"iss"`
		IssuedAt json.Number `json:"iat"`
		Expires  json.Number `json:"exp"`
	}
	if decoder.Decode(&claims) != nil || claims.Issuer != v.issuer {
		return false
	}
	iat, err := claims.IssuedAt.Int64()
	if err != nil {
		return false
	}
	exp, err := claims.Expires.Int64()
	if err != nil {
		return false
	}
	now := v.now().Unix()
	if iat <= 0 || iat > now || exp <= now || exp <= iat || exp > now+10*60 {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, digest[:], signature) == nil
}
