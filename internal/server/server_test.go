package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gh-agent-broker/internal/config"
)

func TestParseGitPath(t *testing.T) {
	repo, suffix, ok := parseGitPath("/git/owner/repo.git/info/refs")
	if !ok {
		t.Fatalf("parseGitPath() failed")
	}
	if repo != "owner/repo" || suffix != "/info/refs" {
		t.Fatalf("repo=%q suffix=%q", repo, suffix)
	}
}

func TestGitOperation(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/git/owner/repo.git/info/refs?service=git-upload-pack", nil)
	if got := gitOperation(req, "/info/refs"); got != "git.upload-pack" {
		t.Fatalf("gitOperation() = %q", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/git/owner/repo.git/git-receive-pack", nil)
	if got := gitOperation(req, "/git-receive-pack"); got != "git.receive-pack" {
		t.Fatalf("gitOperation() = %q", got)
	}
}

func TestReceivePackBranch(t *testing.T) {
	line := "0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/agent/a1/test\x00 report-status\n"
	body := append(pktLine(line), []byte("0000")...)

	if got := receivePackBranch(body); got != "refs/heads/agent/a1/test" {
		t.Fatalf("receivePackBranch() = %q", got)
	}
}

func TestValidateListenAddressRejectsPublicBind(t *testing.T) {
	if err := ValidateListenAddress(":8080"); err == nil {
		t.Fatalf("ValidateListenAddress() error = nil")
	}
}

func TestDiscoveryEndpoints(t *testing.T) {
	srv := &Server{}
	for _, path := range []string{"/", "/operations", "/api/operations", "/docs", "/openapi.json"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		resp := httptest.NewRecorder()
		srv.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want %d; body=%s", path, resp.Code, http.StatusOK, resp.Body.String())
		}
	}
}

func TestOperationsDocumentsV1RESTRoutes(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/operations", nil)
	resp := httptest.NewRecorder()
	(&Server{}).ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
	}
	var out struct {
		Operations []struct {
			Name   string `json:"name"`
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"repo.probe":     "GET /v1/repos/{owner}/{repo}/probe",
		"pull.create":    "POST /v1/repos/{owner}/{repo}/pulls",
		"issue.comment":  "POST /v1/repos/{owner}/{repo}/issues/{number}/comments",
		"policy.dry-run": "POST /v1/policy/dry-run",
	}
	for _, op := range out.Operations {
		if got, ok := want[op.Name]; ok {
			if op.Method+" "+op.Path != got {
				t.Fatalf("operation %s documented as %s %s, want %s", op.Name, op.Method, op.Path, got)
			}
			delete(want, op.Name)
		}
	}
	if len(want) > 0 {
		t.Fatalf("missing documented operations: %#v", want)
	}
}

func TestWhoamiReturnsAuthenticatedAgentPolicySurface(t *testing.T) {
	srv := &Server{cfg: &config.Config{Agents: []config.Agent{{
		ID:             "agent-1",
		Enabled:        true,
		Secret:         "secret",
		Repositories:   []string{"owner/repo"},
		Operations:     []string{"repo.probe"},
		BranchPatterns: []string{"^agent/agent-1/.+$"},
	}}}}
	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.SetBasicAuth("agent-1", "secret")
	resp := httptest.NewRecorder()
	srv.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", resp.Code, http.StatusOK, resp.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["agent_id"] != "agent-1" {
		t.Fatalf("agent_id = %v", out["agent_id"])
	}
	if _, ok := out["secret"]; ok {
		t.Fatalf("whoami exposed secret")
	}
}

func pktLine(line string) []byte {
	n := len(line) + 4
	return []byte(string([]byte{
		hexDigit(n >> 12),
		hexDigit(n >> 8),
		hexDigit(n >> 4),
		hexDigit(n),
	}) + line)
}

func hexDigit(n int) byte {
	n &= 0xf
	if n < 10 {
		return byte('0' + n)
	}
	return byte('a' + n - 10)
}
