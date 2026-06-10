package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gh-agent-broker/internal/api"
	"gh-agent-broker/internal/audit"
	"gh-agent-broker/internal/config"
	"gh-agent-broker/internal/githubapp"
)

func TestFakeGitHubRESTIntegration(t *testing.T) {
	var sawProbe, sawPull, sawIssue, sawComment, sawDismiss, sawResolve bool
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				t.Errorf("token exchange Authorization = %q", r.Header.Get("Authorization"))
			}
			writeTestJSON(t, w, map[string]string{
				"token":      "fake-install-token",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo":
			requireBearer(t, r)
			sawProbe = true
			writeTestJSON(t, w, map[string]interface{}{"id": 1001, "url": "https://api.fake/repos/owner/repo", "html_url": "https://fake/owner/repo"})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/pulls":
			requireBearer(t, r)
			sawPull = true
			body := readBody(t, r)
			if !strings.Contains(body, "Broker-Operation-Id") || !strings.Contains(body, "Agent-Id") {
				t.Fatalf("pull body missing broker metadata: %s", body)
			}
			writeTestJSON(t, w, map[string]interface{}{"id": 2002, "number": 7, "url": "https://api.fake/pulls/7", "html_url": "https://fake/owner/repo/pull/7"})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/issues/7/comments":
			requireBearer(t, r)
			sawComment = true
			body := readBody(t, r)
			if !strings.Contains(body, "Broker-Operation-Id") || !strings.Contains(body, "Agent-Id") {
				t.Fatalf("comment body missing broker metadata: %s", body)
			}
			writeTestJSON(t, w, map[string]interface{}{"id": 3003, "url": "https://api.fake/comments/1", "html_url": "https://fake/owner/repo/pull/7#issuecomment-1"})
		case r.Method == http.MethodPut && r.URL.Path == "/repos/owner/repo/pulls/7/reviews/80/dismissals":
			requireBearer(t, r)
			sawDismiss = true
			body := readBody(t, r)
			if !strings.Contains(body, `"message":"fixed requested changes"`) {
				t.Fatalf("dismiss body missing message: %s", body)
			}
			writeTestJSON(t, w, map[string]interface{}{"id": 80, "state": "DISMISSED", "body": "review body", "user": map[string]string{"login": "roger"}, "html_url": "https://fake/owner/repo/pull/7#pullrequestreview-80"})
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			requireBearer(t, r)
			body := readBody(t, r)
			if !strings.Contains(body, "resolveReviewThread") || !strings.Contains(body, "PRRT_test_thread") {
				t.Fatalf("graphql body missing resolve mutation/thread id: %s", body)
			}
			sawResolve = true
			writeTestJSON(t, w, map[string]interface{}{
				"data": map[string]interface{}{
					"resolveReviewThread": map[string]interface{}{
						"thread": map[string]interface{}{"id": "PRRT_test_thread", "isResolved": true},
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/issues":
			requireBearer(t, r)
			sawIssue = true
			body := readBody(t, r)
			if !strings.Contains(body, "Broker-Operation-Id") || !strings.Contains(body, "Dedupe-Key") || !strings.Contains(body, "agent-reported") {
				t.Fatalf("issue body missing expected metadata/label: %s", body)
			}
			writeTestJSON(t, w, map[string]interface{}{"id": 4004, "number": 8, "url": "https://api.fake/issues/8", "html_url": "https://fake/owner/repo/issues/8"})
		default:
			t.Fatalf("unexpected fake GitHub REST request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer apiServer.Close()

	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{
		ID:           "agent-1",
		Enabled:      true,
		Secret:       "agent-secret",
		Repositories: []string{"owner/repo"},
		Operations:   []string{"repo.probe", "pull.create", "pull.review.dismiss", "pull.review_thread.resolve", "issue.comment", "issue.create"},
		BaseBranches: []string{"main"},
		BranchPatterns: []string{
			"^agent/agent-1/.+$",
		},
	})

	resp := brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/probe", nil)
	assertStatus(t, resp, http.StatusOK)

	resp = brokerRequest(t, broker, http.MethodPost, "/v1/repos/owner/repo/pulls", map[string]interface{}{
		"title":    "agent change",
		"head":     "agent/agent-1/test",
		"base":     "main",
		"body":     "body",
		"metadata": map[string]string{"Agent-Id": "agent-1"},
	})
	assertStatus(t, resp, http.StatusCreated)

	resp = brokerRequest(t, broker, http.MethodPost, "/v1/repos/owner/repo/issues/7/comments", map[string]interface{}{
		"body":     "done",
		"metadata": map[string]string{"Agent-Id": "agent-1"},
	})
	assertStatus(t, resp, http.StatusCreated)

	resp = brokerRequest(t, broker, http.MethodPut, "/v1/repos/owner/repo/pulls/7/reviews/80/dismissal", map[string]interface{}{
		"message":  "fixed requested changes",
		"metadata": map[string]string{"Agent-Id": "agent-1"},
	})
	assertStatus(t, resp, http.StatusOK)

	resp = brokerRequest(t, broker, http.MethodPut, "/v1/repos/owner/repo/pulls/7/review-threads/PRRT_test_thread/resolve", map[string]interface{}{
		"message":  "fixed requested thread",
		"metadata": map[string]string{"Agent-Id": "agent-1"},
	})
	assertStatus(t, resp, http.StatusOK)

	resp = brokerRequest(t, broker, http.MethodPost, "/v1/repos/owner/repo/issues", map[string]interface{}{
		"title":    "bug report",
		"body":     "observed behavior",
		"labels":   []string{"agent-reported"},
		"metadata": map[string]string{"Agent-Id": "agent-1", "Dedupe-Key": "owner/repo:test"},
	})
	assertStatus(t, resp, http.StatusCreated)

	if !sawProbe || !sawPull || !sawIssue || !sawComment || !sawDismiss || !sawResolve {
		t.Fatalf("fake REST handlers were not all exercised: probe=%v pull=%v issue=%v comment=%v dismiss=%v resolve=%v", sawProbe, sawPull, sawIssue, sawComment, sawDismiss, sawResolve)
	}
}

func TestFakeGitHubReadRESTIntegration(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
			writeTestJSON(t, w, map[string]string{
				"token":      "fake-install-token",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls":
			requireBearer(t, r)
			writeTestJSON(t, w, []map[string]interface{}{{
				"id": 1, "number": 5, "state": "open", "title": "curator", "body": "YKM-Curator-Run: cur-1",
				"head": map[string]string{"ref": "curator/cur-1/test", "sha": "abc"},
				"base": map[string]string{"ref": "main"},
				"user": map[string]string{"login": "ykm-curator"},
			}, {
				"id": 2, "number": 6, "state": "open", "title": "other", "body": "none",
				"head": map[string]string{"ref": "agent/other/test", "sha": "def"},
				"base": map[string]string{"ref": "main"},
				"user": map[string]string{"login": "other"},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls/5/files":
			requireBearer(t, r)
			writeTestJSON(t, w, []map[string]interface{}{{"filename": "note.md", "status": "added", "changes": 3}})
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			requireBearer(t, r)
			body := readBody(t, r)
			if !strings.Contains(body, "reviewThreads") {
				t.Fatalf("graphql body missing reviewThreads query: %s", body)
			}
			writeTestJSON(t, w, map[string]interface{}{
				"data": map[string]interface{}{
					"repository": map[string]interface{}{
						"pullRequest": map[string]interface{}{
							"reviewThreads": map[string]interface{}{
								"nodes": []map[string]interface{}{{
									"id":         "PRRT_test_thread",
									"isResolved": false,
									"comments": map[string]interface{}{
										"nodes": []map[string]interface{}{{
											"databaseId": float64(22),
											"body":       "please fix",
											"author":     map[string]string{"login": "roger"},
											"path":       "note.md",
											"url":        "https://fake/owner/repo/pull/5#discussion_r22",
											"createdAt":  "2026-06-10T00:00:00Z",
											"updatedAt":  "2026-06-10T00:00:00Z",
										}},
									},
								}},
							},
						},
					},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/issues/5/comments":
			requireBearer(t, r)
			writeTestJSON(t, w, []map[string]interface{}{{"id": 9, "body": "reviewed", "user": map[string]string{"login": "roger"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/issues":
			requireBearer(t, r)
			writeTestJSON(t, w, []map[string]interface{}{{"id": 10, "number": 11, "state": "open", "title": "followup", "body": "Dedupe-Key: ykm/test", "user": map[string]string{"login": "ykm-curator"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/commits/abc/status":
			requireBearer(t, r)
			writeTestJSON(t, w, map[string]interface{}{"state": "success", "sha": "abc", "total_count": 1, "statuses": []map[string]string{{"context": "ci", "state": "success"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/commits/abc/check-runs":
			requireBearer(t, r)
			writeTestJSON(t, w, map[string]interface{}{"total_count": 1, "check_runs": []map[string]interface{}{{"id": 12, "name": "check", "status": "completed", "conclusion": "success"}}})
		default:
			t.Fatalf("unexpected fake GitHub read request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer apiServer.Close()

	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{
		ID:           "agent-1",
		Enabled:      true,
		Secret:       "agent-secret",
		Repositories: []string{"owner/repo"},
		Operations:   []string{"pull.read", "pull.files.read", "pull.reviews.read", "issue.comments.read", "issue.read", "status.read", "checks.read"},
	})

	resp := brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/pulls?body_marker=YKM-Curator-Run", nil)
	assertStatus(t, resp, http.StatusOK)
	if got := resp.Body.String(); !strings.Contains(got, `"number":5`) || strings.Contains(got, `"number":6`) {
		t.Fatalf("pull marker filter failed: %s", got)
	}
	assertStatus(t, brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/pulls/5/files", nil), http.StatusOK)
	resp = brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/pulls/5/review-threads", nil)
	assertStatus(t, resp, http.StatusOK)
	if got := resp.Body.String(); !strings.Contains(got, `"id":"PRRT_test_thread"`) || !strings.Contains(got, `"resolvable":true`) {
		t.Fatalf("review threads missing graphql thread id/resolvable marker: %s", got)
	}
	assertStatus(t, brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/pulls/5/comments", nil), http.StatusOK)
	assertStatus(t, brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/issues?body_marker=ykm/test", nil), http.StatusOK)
	assertStatus(t, brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/commits/abc/status", nil), http.StatusOK)
	assertStatus(t, brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/commits/abc/check-runs", nil), http.StatusOK)
}

func TestPullReviewWriteDenials(t *testing.T) {
	broker := newTestBroker(t, "https://github.invalid", "https://github.invalid", config.Agent{
		ID:           "agent-1",
		Enabled:      true,
		Secret:       "agent-secret",
		Repositories: []string{"owner/repo"},
		Operations:   []string{"pull.reviews.read"},
	})

	resp := brokerRequest(t, broker, http.MethodPut, "/v1/repos/owner/repo/pulls/7/reviews/80/dismissal", map[string]interface{}{
		"message": "",
	})
	assertStatus(t, resp, http.StatusBadRequest)
	if !strings.Contains(resp.Body.String(), "message is required") {
		t.Fatalf("missing message response = %s", resp.Body.String())
	}

	resp = brokerRequest(t, broker, http.MethodPut, "/v1/repos/owner/repo/pulls/7/reviews/80/dismissal", map[string]interface{}{
		"message": "fixed",
	})
	assertStatus(t, resp, http.StatusForbidden)
	if !strings.Contains(resp.Body.String(), "pull.review.dismiss") {
		t.Fatalf("policy denial should mention operation: %s", resp.Body.String())
	}

	resp = brokerRequest(t, broker, http.MethodPut, "/v1/repos/owner/repo/pulls/7/review-threads/PRRT_test_thread/resolve", map[string]interface{}{
		"message": "",
	})
	assertStatus(t, resp, http.StatusBadRequest)
	if !strings.Contains(resp.Body.String(), "message is required") {
		t.Fatalf("missing message response = %s", resp.Body.String())
	}

	resp = brokerRequest(t, broker, http.MethodPut, "/v1/repos/owner/repo/pulls/7/review-threads/PRRT_test_thread/resolve", map[string]interface{}{
		"message": "fixed",
	})
	assertStatus(t, resp, http.StatusForbidden)
	if !strings.Contains(resp.Body.String(), "pull.review_thread.resolve") {
		t.Fatalf("policy denial should mention operation: %s", resp.Body.String())
	}
}

func TestFakeGitSmartHTTPIntegration(t *testing.T) {
	apiServer := fakeTokenServer(t)
	defer apiServer.Close()

	var sawUploadPack, sawReceivePack bool
	gitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "x-access-token" || pass != "fake-install-token" {
			t.Fatalf("upstream git BasicAuth = %q/%q ok=%v", user, pass, ok)
		}
		if r.Header.Get("X-Agent-ID") != "" || r.Header.Get("X-Agent-Secret") != "" || r.Header.Get("Authorization") == "" {
			t.Fatalf("broker auth headers were not filtered correctly")
		}
		if r.Header.Get("X-Git-Protocol") != "version=2" {
			t.Fatalf("git protocol header was not proxied")
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/owner/repo.git/info/refs" && r.URL.Query().Get("service") == "git-upload-pack":
			sawUploadPack = true
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			writeTestBody(t, w, "upload-pack-ok")
		case r.Method == http.MethodPost && r.URL.Path == "/owner/repo.git/git-receive-pack":
			sawReceivePack = true
			if !strings.Contains(readBody(t, r), "refs/heads/agent/agent-1/test") {
				t.Fatalf("receive-pack body missing branch")
			}
			w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
			writeTestBody(t, w, "receive-pack-ok")
		default:
			t.Fatalf("unexpected fake Git request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer gitServer.Close()

	broker := newTestBroker(t, apiServer.URL, gitServer.URL, config.Agent{
		ID:             "agent-1",
		Enabled:        true,
		Secret:         "agent-secret",
		Repositories:   []string{"owner/repo"},
		Operations:     []string{"git.upload-pack", "git.receive-pack"},
		BranchPatterns: []string{"^refs/heads/agent/agent-1/.+$"},
	})

	req := httptest.NewRequest(http.MethodGet, "/git/owner/repo.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("X-Agent-ID", "agent-1")
	req.Header.Set("X-Agent-Secret", "agent-secret")
	req.Header.Set("X-Git-Protocol", "version=2")
	resp := httptest.NewRecorder()
	broker.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK || resp.Body.String() != "upload-pack-ok" {
		t.Fatalf("upload-pack status/body = %d %q", resp.Code, resp.Body.String())
	}

	body := append(pktLine("0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/agent/agent-1/test\x00 report-status\n"), []byte("0000")...)
	req = httptest.NewRequest(http.MethodPost, "/git/owner/repo.git/git-receive-pack", bytes.NewReader(body))
	req.Header.Set("X-Agent-ID", "agent-1")
	req.Header.Set("X-Agent-Secret", "agent-secret")
	req.Header.Set("X-Git-Protocol", "version=2")
	resp = httptest.NewRecorder()
	broker.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK || resp.Body.String() != "receive-pack-ok" {
		t.Fatalf("receive-pack status/body = %d %q", resp.Code, resp.Body.String())
	}

	if !sawUploadPack || !sawReceivePack {
		t.Fatalf("fake Git handlers were not all exercised: upload=%v receive=%v", sawUploadPack, sawReceivePack)
	}
}

func TestGitPushDenialUsesActionableTextByDefault(t *testing.T) {
	apiServer := fakeTokenServer(t)
	defer apiServer.Close()
	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{
		ID:             "agent-1",
		Enabled:        true,
		Secret:         "agent-secret",
		Repositories:   []string{"owner/repo"},
		Operations:     []string{"git.receive-pack"},
		BranchPatterns: []string{"^refs/heads/agent/agent-1/.+$"},
	})

	body := append(pktLine("0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/main\x00 report-status\n"), []byte("0000")...)
	req := httptest.NewRequest(http.MethodPost, "/git/owner/repo.git/git-receive-pack", bytes.NewReader(body))
	req.SetBasicAuth("agent-1", "agent-secret")
	resp := httptest.NewRecorder()
	broker.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusForbidden)
	}
	got := resp.Body.String()
	for _, want := range []string{"Git operation denied", "operation_id:", "branch", "required_changes", "use a branch matching"} {
		if !strings.Contains(got, want) {
			t.Fatalf("denial text missing %q: %s", want, got)
		}
	}
	if !strings.HasPrefix(resp.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("Content-Type = %q", resp.Header().Get("Content-Type"))
	}
}

func TestGitPolicyDenialCanReturnJSON(t *testing.T) {
	apiServer := fakeTokenServer(t)
	defer apiServer.Close()
	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{
		ID:             "agent-1",
		Enabled:        true,
		Secret:         "agent-secret",
		Repositories:   []string{"owner/repo"},
		Operations:     []string{"git.receive-pack"},
		BranchPatterns: []string{"^refs/heads/agent/agent-1/.+$"},
	})

	body := append(pktLine("0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/main\x00 report-status\n"), []byte("0000")...)
	req := httptest.NewRequest(http.MethodPost, "/git/owner/repo.git/git-receive-pack", bytes.NewReader(body))
	req.SetBasicAuth("agent-1", "agent-secret")
	req.Header.Set("Accept", "application/json")
	resp := httptest.NewRecorder()
	broker.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusForbidden)
	}
	if !strings.HasPrefix(resp.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("Content-Type = %q", resp.Header().Get("Content-Type"))
	}
	var out map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("json denial did not decode: %v; body=%s", err, resp.Body.String())
	}
	if out["code"] != "policy_denied" {
		t.Fatalf("code = %v", out["code"])
	}
}

func TestBranchLifecycleGuardDeniesGitPushToClosedPullBranch(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
			writeTestJSON(t, w, map[string]string{
				"token":      "fake-install-token",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls":
			requireBearer(t, r)
			if r.URL.Query().Get("state") != "all" || r.URL.Query().Get("head") != "owner:agent/agent-1/test" {
				t.Fatalf("unexpected pull lifecycle query: %s", r.URL.RawQuery)
			}
			writeTestJSON(t, w, []map[string]interface{}{{
				"id": 6, "number": 6, "state": "closed", "title": "done", "merged": true,
				"head":     map[string]string{"ref": "agent/agent-1/test", "sha": "abc"},
				"base":     map[string]string{"ref": "main"},
				"html_url": "https://fake/owner/repo/pull/6",
			}})
		default:
			t.Fatalf("unexpected fake GitHub request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer apiServer.Close()

	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{
		ID:             "agent-1",
		Enabled:        true,
		Secret:         "agent-secret",
		Repositories:   []string{"owner/repo"},
		Operations:     []string{"git.receive-pack"},
		BranchPatterns: []string{"^refs/heads/agent/agent-1/.+$"},
		BranchGuard:    config.BranchLifecycleGuard{Mode: "enforce"},
	})

	body := append(pktLine("0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/agent/agent-1/test\x00 report-status\n"), []byte("0000")...)
	req := httptest.NewRequest(http.MethodPost, "/git/owner/repo.git/git-receive-pack", bytes.NewReader(body))
	req.SetBasicAuth("agent-1", "agent-secret")
	resp := httptest.NewRecorder()
	broker.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", resp.Code, http.StatusForbidden, resp.Body.String())
	}
	got := resp.Body.String()
	for _, want := range []string{"branch_lifecycle", "PR #6", "fresh branch"} {
		if !strings.Contains(got, want) {
			t.Fatalf("denial text missing %q: %s", want, got)
		}
	}
}

func TestBranchLifecycleGuardDeniesPullCreateFromClosedPullBranch(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
			writeTestJSON(t, w, map[string]string{
				"token":      "fake-install-token",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls":
			requireBearer(t, r)
			writeTestJSON(t, w, []map[string]interface{}{{
				"id": 7, "number": 7, "state": "closed", "title": "closed", "merged": false,
				"head":     map[string]string{"ref": "agent/agent-1/test", "sha": "abc"},
				"base":     map[string]string{"ref": "main"},
				"html_url": "https://fake/owner/repo/pull/7",
			}})
		default:
			t.Fatalf("unexpected fake GitHub request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer apiServer.Close()

	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{
		ID:             "agent-1",
		Enabled:        true,
		Secret:         "agent-secret",
		Repositories:   []string{"owner/repo"},
		Operations:     []string{"pull.create"},
		BaseBranches:   []string{"main"},
		BranchPatterns: []string{"^agent/agent-1/.+$"},
		BranchGuard:    config.BranchLifecycleGuard{Mode: "enforce"},
	})

	resp := brokerRequest(t, broker, http.MethodPost, "/v1/repos/owner/repo/pulls", map[string]interface{}{
		"title": "follow-up",
		"head":  "agent/agent-1/test",
		"base":  "main",
	})
	assertStatus(t, resp, http.StatusForbidden)
	var out struct {
		FailedChecks []api.FailedCheck `json:"failed_checks"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("json denial did not decode: %v; body=%s", err, resp.Body.String())
	}
	if len(out.FailedChecks) != 1 || out.FailedChecks[0].Dimension != "branch_lifecycle" {
		t.Fatalf("unexpected failed checks: %#v", out.FailedChecks)
	}
}

func TestBranchLifecycleGuardAllowsPullCreateForOpenPullBranch(t *testing.T) {
	var sawCreate bool
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
			writeTestJSON(t, w, map[string]string{
				"token":      "fake-install-token",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls":
			requireBearer(t, r)
			writeTestJSON(t, w, []map[string]interface{}{{
				"id": 8, "number": 8, "state": "open", "title": "active",
				"head": map[string]string{"ref": "agent/agent-1/test", "sha": "abc"},
				"base": map[string]string{"ref": "main"},
			}, {
				"id": 10, "number": 10, "state": "closed", "title": "other branch", "merged": true,
				"head": map[string]string{"ref": "agent/agent-1/other", "sha": "def"},
				"base": map[string]string{"ref": "main"},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/pulls":
			requireBearer(t, r)
			sawCreate = true
			writeTestJSON(t, w, map[string]interface{}{"id": 9, "number": 9, "url": "https://api.fake/pulls/9", "html_url": "https://fake/owner/repo/pull/9"})
		default:
			t.Fatalf("unexpected fake GitHub request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer apiServer.Close()

	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{
		ID:             "agent-1",
		Enabled:        true,
		Secret:         "agent-secret",
		Repositories:   []string{"owner/repo"},
		Operations:     []string{"pull.create"},
		BaseBranches:   []string{"main"},
		BranchPatterns: []string{"^agent/agent-1/.+$"},
		BranchGuard:    config.BranchLifecycleGuard{Mode: "enforce"},
	})

	resp := brokerRequest(t, broker, http.MethodPost, "/v1/repos/owner/repo/pulls", map[string]interface{}{
		"title": "follow-up",
		"head":  "agent/agent-1/test",
		"base":  "main",
	})
	assertStatus(t, resp, http.StatusCreated)
	if !sawCreate {
		t.Fatalf("pull create was not called")
	}
}

func TestBranchLifecycleGuardFailsClosedWhenLookupFails(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
			writeTestJSON(t, w, map[string]string{
				"token":      "fake-install-token",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls":
			requireBearer(t, r)
			http.Error(w, "temporary failure", http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected fake GitHub request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer apiServer.Close()

	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{
		ID:             "agent-1",
		Enabled:        true,
		Secret:         "agent-secret",
		Repositories:   []string{"owner/repo"},
		Operations:     []string{"pull.create"},
		BaseBranches:   []string{"main"},
		BranchPatterns: []string{"^agent/agent-1/.+$"},
		BranchGuard:    config.BranchLifecycleGuard{Mode: "enforce"},
	})

	resp := brokerRequest(t, broker, http.MethodPost, "/v1/repos/owner/repo/pulls", map[string]interface{}{
		"title": "follow-up",
		"head":  "agent/agent-1/test",
		"base":  "main",
	})
	assertStatus(t, resp, http.StatusForbidden)
	if !strings.Contains(resp.Body.String(), "could not verify") {
		t.Fatalf("denial missing lookup failure message: %s", resp.Body.String())
	}
}

func TestBranchLifecycleGuardWarnModeAllowsLookupFailure(t *testing.T) {
	var sawCreate bool
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
			writeTestJSON(t, w, map[string]string{
				"token":      "fake-install-token",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls":
			requireBearer(t, r)
			http.Error(w, "temporary failure", http.StatusInternalServerError)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/pulls":
			requireBearer(t, r)
			sawCreate = true
			writeTestJSON(t, w, map[string]interface{}{"id": 11, "number": 11, "url": "https://api.fake/pulls/11", "html_url": "https://fake/owner/repo/pull/11"})
		default:
			t.Fatalf("unexpected fake GitHub request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer apiServer.Close()

	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{
		ID:             "agent-1",
		Enabled:        true,
		Secret:         "agent-secret",
		Repositories:   []string{"owner/repo"},
		Operations:     []string{"pull.create"},
		BaseBranches:   []string{"main"},
		BranchPatterns: []string{"^agent/agent-1/.+$"},
		BranchGuard:    config.BranchLifecycleGuard{Mode: "warn"},
	})

	resp := brokerRequest(t, broker, http.MethodPost, "/v1/repos/owner/repo/pulls", map[string]interface{}{
		"title": "follow-up",
		"head":  "agent/agent-1/test",
		"base":  "main",
	})
	assertStatus(t, resp, http.StatusCreated)
	if !sawCreate {
		t.Fatalf("pull create was not called")
	}
}

func newTestBroker(t *testing.T, apiBaseURL, gitBaseURL string, agent config.Agent) *Server {
	t.Helper()
	keyPath := writeTestPrivateKey(t)
	cfg := &config.Config{
		Audit: config.AuditConfig{Path: filepath.Join(t.TempDir(), "audit.jsonl")},
		GitHub: config.GitHubConfig{
			AppID:          1,
			PrivateKeyPath: keyPath,
			APIBaseURL:     apiBaseURL,
			GitBaseURL:     gitBaseURL,
			Installations:  map[string]int64{"owner/repo": 42},
		},
		Agents: []config.Agent{agent},
	}
	auditLog, err := audit.New(cfg.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := auditLog.Close(); err != nil {
			t.Fatalf("close audit log: %v", err)
		}
	})
	gh, err := githubapp.New(cfg.GitHub)
	if err != nil {
		t.Fatal(err)
	}
	return New("", cfg, gh, auditLog)
}

func writeTestPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b := x509.MarshalPKCS1PrivateKey(key)
	path := filepath.Join(t.TempDir(), "github-app.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/42/access_tokens" {
			t.Fatalf("unexpected token request: %s %s", r.Method, r.URL.Path)
		}
		writeTestJSON(t, w, map[string]string{
			"token":      "fake-install-token",
			"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	}))
}

func brokerRequest(t *testing.T, broker *Server, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.SetBasicAuth("agent-1", "agent-secret")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp := httptest.NewRecorder()
	broker.ServeHTTP(resp, req)
	return resp
}

func assertStatus(t *testing.T, resp *httptest.ResponseRecorder, want int) {
	t.Helper()
	if resp.Code != want {
		t.Fatalf("status = %d, want %d; body=%s", resp.Code, want, resp.Body.String())
	}
}

func requireBearer(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Header.Get("Authorization") != "Bearer fake-install-token" {
		t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
	}
}

func readBody(t *testing.T, r *http.Request) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}

func writeTestBody(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
}
