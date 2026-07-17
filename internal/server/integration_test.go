package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	"gh-agent-broker/internal/pushtripwire"
)

func TestFakeGitHubRESTIntegration(t *testing.T) {
	var sawProbe, sawPull, sawIssue, sawDismiss, sawResolve, sawGraphQLDismiss bool
	var sawComment, sawAddLabels, sawRemoveLabel int
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
			sawComment++
			body := readBody(t, r)
			if !strings.Contains(body, "Broker-Operation-Id") || !strings.Contains(body, "Agent-Id") {
				t.Fatalf("comment body missing broker metadata: %s", body)
			}
			writeTestJSON(t, w, map[string]interface{}{"id": 3003, "url": "https://api.fake/comments/1", "html_url": "https://fake/owner/repo/pull/7#issuecomment-1", "created_at": "2026-06-10T00:00:00Z"})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls/7/reviews/80":
			requireBearer(t, r)
			writeTestJSON(t, w, map[string]interface{}{"id": 80, "node_id": "PRR_numeric", "state": "CHANGES_REQUESTED", "body": "review body", "user": map[string]string{"login": "roger"}, "html_url": "https://fake/owner/repo/pull/7#pullrequestreview-80"})
		case r.Method == http.MethodPut && r.URL.Path == "/repos/owner/repo/pulls/7/reviews/80/dismissals":
			requireBearer(t, r)
			sawDismiss = true
			body := readBody(t, r)
			if !strings.Contains(body, `"message":"fixed requested changes"`) {
				t.Fatalf("dismiss body missing message: %s", body)
			}
			writeTestJSON(t, w, map[string]interface{}{"id": 80, "node_id": "PRR_numeric", "state": "DISMISSED", "body": "review body", "user": map[string]string{"login": "roger"}, "html_url": "https://fake/owner/repo/pull/7#pullrequestreview-80"})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/issues/7/labels":
			requireBearer(t, r)
			sawAddLabels++
			body := readBody(t, r)
			if !strings.Contains(body, "ym-curator: waiting-review") {
				t.Fatalf("label add body missing label: %s", body)
			}
			writeTestJSON(t, w, []map[string]string{{"name": "ym-curator: waiting-review"}, {"name": "ym-curator: needs work"}})
		case r.Method == http.MethodDelete && r.URL.Path == "/repos/owner/repo/issues/7/labels/ym-curator: needs work":
			requireBearer(t, r)
			sawRemoveLabel++
			writeTestJSON(t, w, []map[string]string{{"name": "ym-curator: waiting-review"}})
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			requireBearer(t, r)
			body := readBody(t, r)
			switch {
			case strings.Contains(body, "dismissPullRequestReview") && strings.Contains(body, "PRR_graphql"):
				sawGraphQLDismiss = true
				writeTestJSON(t, w, map[string]interface{}{
					"data": map[string]interface{}{
						"dismissPullRequestReview": map[string]interface{}{
							"pullRequestReview": map[string]interface{}{"id": "PRR_graphql", "databaseId": 81, "state": "DISMISSED", "body": "review body", "url": "https://fake/owner/repo/pull/7#pullrequestreview-81", "author": map[string]string{"login": "roger"}},
						},
					},
				})
			case strings.Contains(body, "PullRequestReview") && strings.Contains(body, "PRR_graphql"):
				writeTestJSON(t, w, map[string]interface{}{
					"data": map[string]interface{}{
						"node": map[string]interface{}{"id": "PRR_graphql", "databaseId": 81, "state": "CHANGES_REQUESTED", "body": "review body", "url": "https://fake/owner/repo/pull/7#pullrequestreview-81", "author": map[string]string{"login": "roger"}},
					},
				})
			case strings.Contains(body, "addPullRequestReviewThreadReply") && strings.Contains(body, "fixed requested thread"):
				writeTestJSON(t, w, map[string]interface{}{
					"data": map[string]interface{}{
						"addPullRequestReviewThreadReply": map[string]interface{}{"comment": map[string]interface{}{"id": "PRRC_reply"}},
					},
				})
			case strings.Contains(body, "resolveReviewThread") && strings.Contains(body, "PRRT_test_thread"):
				sawResolve = true
				writeTestJSON(t, w, map[string]interface{}{
					"data": map[string]interface{}{
						"resolveReviewThread": map[string]interface{}{
							"thread": map[string]interface{}{"id": "PRRT_test_thread", "isResolved": true},
						},
					},
				})
			case strings.Contains(body, "PullRequestReviewThread") && strings.Contains(body, "PRRT_test_thread"):
				writeTestJSON(t, w, map[string]interface{}{
					"data": map[string]interface{}{
						"node": map[string]interface{}{
							"id":         "PRRT_test_thread",
							"isResolved": false,
							"path":       "note.md",
							"line":       12,
							"comments": map[string]interface{}{
								"nodes": []map[string]interface{}{{
									"id":         "PRRC_1",
									"databaseId": 22,
									"body":       "please fix",
									"author":     map[string]string{"login": "roger"},
									"path":       "note.md",
									"line":       12,
									"url":        "https://fake/owner/repo/pull/7#discussion_r22",
								}},
							},
						},
					},
				})
			default:
				t.Fatalf("unexpected graphql body: %s", body)
			}
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
		Operations:   []string{"repo.probe", "pull.create", "pull.review.dismiss", "pull.review_thread.resolve", "issue.comment", "issue.label.add", "issue.label.remove", "issue.create"},
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

	resp = brokerRequestHeaders(t, broker, http.MethodPost, "/v1/repos/owner/repo/issues/7/comments", map[string]interface{}{
		"body":     "done",
		"metadata": map[string]string{"Agent-Id": "agent-1"},
	}, map[string]string{"Idempotency-Key": "pr-repair:7:abc:comment"})
	assertStatus(t, resp, http.StatusCreated)
	resp = brokerRequestHeaders(t, broker, http.MethodPost, "/v1/repos/owner/repo/issues/7/comments", map[string]interface{}{
		"body":     "done",
		"metadata": map[string]string{"Agent-Id": "agent-1"},
	}, map[string]string{"Idempotency-Key": "pr-repair:7:abc:comment"})
	assertStatus(t, resp, http.StatusCreated)

	resp = brokerRequest(t, broker, http.MethodPut, "/v1/repos/owner/repo/pulls/7/reviews/80/dismissal", map[string]interface{}{
		"message":  "fixed requested changes",
		"metadata": map[string]string{"Agent-Id": "agent-1"},
	})
	assertStatus(t, resp, http.StatusOK)
	resp = brokerRequest(t, broker, http.MethodPut, "/v1/repos/owner/repo/pulls/7/reviews/PRR_graphql/dismissal", map[string]interface{}{
		"message":  "fixed requested changes",
		"metadata": map[string]string{"Agent-Id": "agent-1"},
	})
	assertStatus(t, resp, http.StatusOK)

	resp = brokerRequest(t, broker, http.MethodPut, "/v1/repos/owner/repo/pulls/7/review-threads/PRRT_test_thread/resolve", map[string]interface{}{
		"message":  "fixed requested thread",
		"metadata": map[string]string{"Agent-Id": "agent-1"},
	})
	assertStatus(t, resp, http.StatusOK)

	resp = brokerRequest(t, broker, http.MethodPost, "/v1/repos/owner/repo/issues/7/labels", map[string]interface{}{
		"labels": []string{"ym-curator: waiting-review"},
	})
	assertStatus(t, resp, http.StatusOK)
	resp = brokerRequest(t, broker, http.MethodDelete, "/v1/repos/owner/repo/issues/7/labels/ym-curator:%20needs%20work", nil)
	assertStatus(t, resp, http.StatusOK)

	resp = brokerRequest(t, broker, http.MethodPost, "/v1/repos/owner/repo/issues", map[string]interface{}{
		"title":    "bug report",
		"body":     "observed behavior",
		"labels":   []string{"agent-reported"},
		"metadata": map[string]string{"Agent-Id": "agent-1", "Dedupe-Key": "owner/repo:test"},
	})
	assertStatus(t, resp, http.StatusCreated)

	if !sawProbe || !sawPull || !sawIssue || sawComment != 1 || !sawDismiss || !sawGraphQLDismiss || !sawResolve || sawAddLabels != 1 || sawRemoveLabel != 1 {
		t.Fatalf("fake REST handlers were not all exercised: probe=%v pull=%v issue=%v comment=%d dismiss=%v graphqlDismiss=%v resolve=%v addLabels=%d removeLabel=%d", sawProbe, sawPull, sawIssue, sawComment, sawDismiss, sawGraphQLDismiss, sawResolve, sawAddLabels, sawRemoveLabel)
	}
}

func TestCredentialShapedTextIsBlockedBeforeGitHubTokenIssuance(t *testing.T) {
	upstreamRequests := 0
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests++
		w.WriteHeader(http.StatusTeapot)
	}))
	defer apiServer.Close()
	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{
		ID:             "agent-1",
		Enabled:        true,
		Secret:         "agent-secret",
		Repositories:   []string{"owner/repo"},
		Operations:     []string{"pull.create", "pull.review.dismiss", "pull.review_thread.resolve", "issue.comment", "issue.create"},
		BaseBranches:   []string{"main"},
		BranchPatterns: []string{"^agent/agent-1/.+$"},
	})
	canary := "PR10-CREDENTIAL-CANARY:github-only-test"
	encodedCanary := base64.RawURLEncoding.EncodeToString([]byte(canary))
	tests := []struct {
		name, method, path string
		body               map[string]interface{}
	}{
		{"pull", http.MethodPost, "/v1/repos/owner/repo/pulls", map[string]interface{}{"title": "change", "head": "agent/agent-1/test", "base": "main", "body": canary}},
		{"issue", http.MethodPost, "/v1/repos/owner/repo/issues", map[string]interface{}{"title": "report", "body": canary}},
		{"comment", http.MethodPost, "/v1/repos/owner/repo/issues/7/comments", map[string]interface{}{"body": canary}},
		{"dismissal", http.MethodPut, "/v1/repos/owner/repo/pulls/7/reviews/80/dismissal", map[string]interface{}{"message": canary}},
		{"thread", http.MethodPut, "/v1/repos/owner/repo/pulls/7/review-threads/PRRT_test_thread/resolve", map[string]interface{}{"message": canary}},
		{"encoded-comment", http.MethodPost, "/v1/repos/owner/repo/issues/8/comments", map[string]interface{}{"body": "AA" + encodedCanary + "AA"}},
		{"split-pull", http.MethodPost, "/v1/repos/owner/repo/pulls", map[string]interface{}{"title": "PR10-CREDENTIAL-", "body": "CANARY:split-field-test", "head": "agent/agent-1/split", "base": "main"}},
		{"split-encoded-pull", http.MethodPost, "/v1/repos/owner/repo/pulls", map[string]interface{}{"title": ("AA" + encodedCanary)[:len(encodedCanary)/2], "body": ("AA" + encodedCanary)[len(encodedCanary)/2:] + "AA", "head": "agent/agent-1/split-encoded", "base": "main"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := brokerRequest(t, broker, tc.method, tc.path, tc.body)
			assertStatus(t, resp, http.StatusUnprocessableEntity)
			if strings.Contains(resp.Body.String(), canary) || strings.Contains(resp.Body.String(), encodedCanary) || !strings.Contains(resp.Body.String(), `"code":"security_egress_blocked"`) {
				t.Fatalf("unsafe response = %s", resp.Body.String())
			}
		})
	}
	if upstreamRequests != 0 {
		t.Fatalf("blocked output caused %d GitHub/token requests", upstreamRequests)
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
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls/5/reviews":
			requireBearer(t, r)
			writeTestJSON(t, w, []map[string]interface{}{{
				"id": 80, "node_id": "PRR_test_review", "state": "CHANGES_REQUESTED", "body": "needs work",
				"user": map[string]string{"login": "roger"}, "submitted_at": "2026-06-10T18:25:37Z", "html_url": "https://fake/owner/repo/pull/5#pullrequestreview-80",
			}})
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
									"path":       "note.md",
									"line":       12,
									"comments": map[string]interface{}{
										"nodes": []map[string]interface{}{{
											"id":         "PRRC_test_comment",
											"databaseId": 22,
											"body":       "please fix",
											"author":     map[string]string{"login": "roger"},
											"path":       "note.md",
											"line":       12,
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
	resp = brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/pulls/5/reviews", nil)
	assertStatus(t, resp, http.StatusOK)
	if got := resp.Body.String(); !strings.Contains(got, `"id":"PRR_test_review"`) || !strings.Contains(got, `"database_id":80`) || !strings.Contains(got, `"state":"CHANGES_REQUESTED"`) {
		t.Fatalf("reviews missing node/database id/state: %s", got)
	}
	resp = brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/pulls/5/review-threads", nil)
	assertStatus(t, resp, http.StatusOK)
	if got := resp.Body.String(); !strings.Contains(got, `"id":"PRRT_test_thread"`) || !strings.Contains(got, `"resolvable":true`) {
		t.Fatalf("review threads missing graphql thread id/resolvable marker: %s", got)
	}
	if got := resp.Body.String(); !strings.Contains(got, `"id":"PRRC_test_comment"`) || !strings.Contains(got, `"database_id":22`) || !strings.Contains(got, `"line":12`) {
		t.Fatalf("review threads missing comment identity/path context: %s", got)
	}
	assertStatus(t, brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/pulls/5/comments", nil), http.StatusOK)
	assertStatus(t, brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/issues?body_marker=ykm/test", nil), http.StatusOK)
	assertStatus(t, brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/commits/abc/status", nil), http.StatusOK)
	assertStatus(t, brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/commits/abc/check-runs", nil), http.StatusOK)
}

func TestReadAccessMapsGitHubNotFoundAndAuditsCategory(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
			writeTestJSON(t, w, map[string]string{
				"token":      "fake-install-token",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/issues/99":
			requireBearer(t, r)
			w.WriteHeader(http.StatusNotFound)
			writeTestJSON(t, w, map[string]string{"message": "Not Found", "status": "404"})
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
		Operations:   []string{"issue.read"},
	})
	resp := brokerRequest(t, broker, http.MethodGet, "/v1/repos/owner/repo/issues/99", nil)
	assertStatus(t, resp, http.StatusNotFound)
	var body api.ErrorResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Code != "github_not_found" {
		t.Fatalf("code = %q, want github_not_found; body=%s", body.Code, resp.Body.String())
	}
	events := readBrokerAuditEvents(t, broker.cfg.Audit.Path)
	ev := lastAuditEventForOperation(t, events, "issue.read")
	if ev.Extra["github_error_code"] != "github_not_found" || ev.Extra["github_error_category"] != "not_found" || ev.Extra["broker_status"] != float64(http.StatusNotFound) || ev.Extra["github_status"] != float64(http.StatusNotFound) {
		t.Fatalf("audit extra = %#v", ev.Extra)
	}
}

func TestClassifyGitHubReadError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "forbidden", err: githubapp.APIError{StatusCode: http.StatusForbidden, Body: `{"message":"Forbidden"}`}, wantStatus: http.StatusForbidden, wantCode: "github_forbidden"},
		{name: "rate limited status", err: githubapp.APIError{StatusCode: http.StatusTooManyRequests, Body: `{"message":"rate limit"}`}, wantStatus: http.StatusTooManyRequests, wantCode: "github_rate_limited"},
		{name: "rate limited body", err: githubapp.APIError{StatusCode: http.StatusForbidden, Body: `{"message":"API rate limit exceeded"}`}, wantStatus: http.StatusTooManyRequests, wantCode: "github_rate_limited"},
		{name: "timeout", err: context.DeadlineExceeded, wantStatus: http.StatusGatewayTimeout, wantCode: "github_timeout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotStatus, gotCode, _, extra := classifyGitHubReadError(tc.err)
			if gotStatus != tc.wantStatus || gotCode != tc.wantCode {
				t.Fatalf("classify = status %d code %q extra %#v, want status %d code %q", gotStatus, gotCode, extra, tc.wantStatus, tc.wantCode)
			}
		})
	}
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
	var expectedReceivePackLength int64
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
			if r.ContentLength != expectedReceivePackLength {
				t.Fatalf("receive-pack ContentLength=%d want=%d", r.ContentLength, expectedReceivePackLength)
			}
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
	expectedReceivePackLength = int64(len(body))
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

func TestLargeOpaquePackIsStreamedAfterBoundedPrefix(t *testing.T) {
	apiServer := fakeTokenServer(t)
	defer apiServer.Close()
	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{ID: "agent-1", Enabled: true, Secret: "agent-secret", Repositories: []string{"owner/repo"}, Operations: []string{"git.receive-pack"}, BranchPatterns: []string{"^refs/heads/agent/agent-1/.+$"}})
	prefix := append(pktLine(strings.Repeat("0", 40)+" "+strings.Repeat("1", 40)+" refs/heads/agent/agent-1/large\x00 report-status\n"), []byte("0000")...)
	packSize := int64(32 << 20)
	source := &countingReadCloser{Reader: io.MultiReader(bytes.NewReader(prefix), io.LimitReader(zeroReader{}, packSize))}
	total := int64(len(prefix)) + packSize
	broker.http = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if source.read != int64(len(prefix)) {
			return nil, fmt.Errorf("broker consumed %d bytes before upstream, want command prefix %d", source.read, len(prefix))
		}
		if req.ContentLength != total {
			return nil, fmt.Errorf("upstream ContentLength=%d want=%d", req.ContentLength, total)
		}
		n, err := io.Copy(io.Discard, req.Body)
		if err != nil {
			return nil, err
		}
		if n != total {
			return nil, fmt.Errorf("forwarded bytes=%d want=%d", n, total)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/x-git-receive-pack-result"}}, Body: io.NopCloser(strings.NewReader("receive-pack-ok"))}, nil
	})}
	req := httptest.NewRequest(http.MethodPost, "/git/owner/repo.git/git-receive-pack", source)
	req.ContentLength = total
	req.SetBasicAuth("agent-1", "agent-secret")
	resp := httptest.NewRecorder()
	broker.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK || resp.Body.String() != "receive-pack-ok" {
		t.Fatalf("response=%d %q", resp.Code, resp.Body.String())
	}
	if source.read != total {
		t.Fatalf("source read=%d want=%d", source.read, total)
	}
}

type countingReadCloser struct {
	io.Reader
	read int64
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.read += int64(n)
	return n, err
}
func (*countingReadCloser) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPushTripwireFirstPushIncludesIntroducedThenRemovedAndDeletedBytes(t *testing.T) {
	before, first, after := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	tree0, tree1, tree2, blobSHA := strings.Repeat("d", 40), strings.Repeat("e", 40), strings.Repeat("f", 40), strings.Repeat("1", 40)
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens" {
			writeTestJSON(t, w, map[string]string{"token": "fake-install-token", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)})
			return
		}
		requireBearer(t, r)
		switch r.URL.Path {
		case "/repos/owner/repo/git/ref/heads/main":
			writeTestJSON(t, w, map[string]interface{}{"object": map[string]string{"sha": before}})
		case "/repos/owner/repo/compare/" + before + "..." + after:
			writeTestJSON(t, w, map[string]interface{}{"status": "diverged", "total_commits": 2, "commits": []map[string]string{{"sha": first}, {"sha": after}}})
		case "/repos/owner/repo/commits/" + before:
			writeTestJSON(t, w, map[string]interface{}{"sha": before, "commit": map[string]interface{}{"message": "base", "tree": map[string]string{"sha": tree0}}, "parents": []interface{}{}})
		case "/repos/owner/repo/commits/" + first:
			writeTestJSON(t, w, map[string]interface{}{"sha": first, "commit": map[string]interface{}{"message": "introduce canary", "tree": map[string]string{"sha": tree1}}, "parents": []map[string]string{{"sha": before}}})
		case "/repos/owner/repo/commits/" + after:
			writeTestJSON(t, w, map[string]interface{}{"sha": after, "commit": map[string]interface{}{"message": "remove canary", "tree": map[string]string{"sha": tree2}}, "parents": []map[string]string{{"sha": first}}})
		case "/repos/owner/repo/git/trees/" + tree0:
			writeTestJSON(t, w, map[string]interface{}{"truncated": false, "tree": []interface{}{}})
		case "/repos/owner/repo/git/trees/" + tree1:
			writeTestJSON(t, w, map[string]interface{}{"truncated": false, "tree": []map[string]interface{}{{"path": "canary.txt", "type": "blob", "sha": blobSHA, "size": 6}}})
		case "/repos/owner/repo/git/trees/" + tree2:
			writeTestJSON(t, w, map[string]interface{}{"truncated": false, "tree": []interface{}{}})
		case "/repos/owner/repo/git/blobs/" + blobSHA:
			writeTestJSON(t, w, map[string]interface{}{"encoding": "base64", "size": 6, "content": base64.StdEncoding.EncodeToString([]byte("canary"))})
		default:
			t.Fatalf("unexpected material request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
	}))
	defer apiServer.Close()
	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{ID: "agent-1", Enabled: true, Secret: "agent-secret", Repositories: []string{"owner/repo"}})
	cfg, _ := broker.snapshot()
	cfg.PushTripwire = config.PushTripwireConfig{Enabled: true, ScannerID: "scanner", ScannerSecret: "scan-secret", StatePath: filepath.Join(t.TempDir(), "tripwire.db"), Repositories: map[string]config.PushTripwireRepository{"owner/repo": {BaseRef: "refs/heads/main", RefPatterns: []string{"^refs/heads/agent/agent-1/.+$"}}}, Bounds: config.PushTripwireBounds{MaxCommits: 10, MaxPaths: 10, MaxCommitMessageBytes: 1024, MaxBlobBytes: 1024, MaxTotalBytes: 8192}}
	store, err := pushtripwire.Open(cfg.PushTripwire.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	broker.tripwire = store
	requestBody, err := json.Marshal(map[string]string{"version": pushtripwire.Version, "delivery_id": "delivery-1", "repository": "owner/repo", "ref": "refs/heads/agent/agent-1/new", "before": strings.Repeat("0", 40), "after": after})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/security/push-tripwire/material", bytes.NewReader(requestBody))
	req.Header.Set("Authorization", "Bearer scan-secret")
	resp := httptest.NewRecorder()
	broker.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var out pushtripwire.MaterialResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Complete || out.Before != strings.Repeat("0", 40) || len(out.Commits) != 2 || len(out.Files) != 2 {
		t.Fatalf("unexpected material: %+v", out)
	}
	if out.Files[0].Side != "after" || out.Files[1].Side != "before" {
		t.Fatalf("missing introduced/deleted byte sides: %+v", out.Files)
	}
	for _, file := range out.Files {
		decoded, err := base64.StdEncoding.DecodeString(file.ContentBase64)
		if err != nil {
			t.Fatal(err)
		}
		if string(decoded) != "canary" {
			t.Fatalf("missing canary bytes: %+v", file)
		}
	}
	deniedBody, err := json.Marshal(map[string]string{"version": pushtripwire.Version, "delivery_id": "delivery-2", "repository": "owner/repo", "ref": "refs/heads/main", "before": before, "after": after})
	if err != nil {
		t.Fatal(err)
	}
	deniedReq := httptest.NewRequest(http.MethodPost, "/v1/security/push-tripwire/material", bytes.NewReader(deniedBody))
	deniedReq.Header.Set("Authorization", "Bearer scan-secret")
	deniedResp := httptest.NewRecorder()
	broker.ServeHTTP(deniedResp, deniedReq)
	if deniedResp.Code != http.StatusForbidden {
		t.Fatalf("unreviewed ref status=%d body=%s", deniedResp.Code, deniedResp.Body.String())
	}
}

func TestReloadPreservesTripwireIssuanceHalt(t *testing.T) {
	apiServer := fakeTokenServer(t)
	defer apiServer.Close()
	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{ID: "agent-1", Enabled: true, Secret: "agent-secret", Repositories: []string{"owner/repo"}})
	cfg, _ := broker.snapshot()
	statePath := filepath.Join(t.TempDir(), "tripwire.db")
	cfg.PushTripwire = config.PushTripwireConfig{Enabled: true, ScannerID: "scanner", ScannerSecret: "secret", StatePath: statePath, Repositories: map[string]config.PushTripwireRepository{"owner/repo": {BaseRef: "refs/heads/main", RefPatterns: []string{"^refs/heads/agent/.+$"}}}, ResponseProfiles: map[string]config.PushTripwireResponseProfile{"curator": {Generation: 7, AllowHalt: true}}, Bounds: config.PushTripwireBounds{MaxCommits: 100, MaxPaths: 300, MaxCommitMessageBytes: 64 << 10, MaxBlobBytes: 1 << 20, MaxTotalBytes: 16 << 20}}
	store, err := pushtripwire.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	broker.tripwire = store
	if err := store.ReplaceEnforcementCatalog(context.Background(), map[string]int64{"curator": 7}); err != nil {
		t.Fatal(err)
	}
	req := pushtripwire.ResponseRequest{Version: pushtripwire.Version, FindingID: "finding", DeliveryID: "delivery", Repository: "owner/repo", Ref: "refs/heads/agent/test", Before: strings.Repeat("a", 40), After: strings.Repeat("b", 40), Severity: "high", ReasonCode: "seeded_canary_match", Profile: "curator", ProfileGeneration: 7, Actions: []string{"halt_issuance"}}
	if _, err := store.Apply(context.Background(), "reload-proof", req, nil); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "broker.yaml")
	body := fmt.Sprintf("github:\n  app_id: 1\n  private_key_path: %q\n  api_base_url: %q\n  git_base_url: https://github.invalid\n  installations:\n    owner/repo: 42\npush_tripwire:\n  enabled: true\n  scanner_id: scanner\n  scanner_secret: secret\n  state_path: %q\n  repositories:\n    owner/repo:\n      base_ref: refs/heads/main\n      ref_patterns: ['^refs/heads/agent/.+$']\n  response_profiles:\n    curator:\n      generation: 7\n      allow_halt: true\n", cfg.GitHub.PrivateKeyPath, apiServer.URL, statePath)
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	broker.configPath = configPath
	if err := broker.Reload(); err != nil {
		t.Fatal(err)
	}
	_, _, reloaded, _ := broker.pushTripwireSnapshot()
	if reloaded != store {
		t.Fatal("reload replaced durable tripwire store")
	}
	if err := reloaded.CheckIssuance(context.Background(), "curator", 7); err == nil {
		t.Fatal("reload abandoned issuance halt")
	}
}

func TestPushTripwireRespondReportsHaltedOnlyAfterAuthorityRegistration(t *testing.T) {
	apiServer := fakeTokenServer(t)
	defer apiServer.Close()
	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{ID: "agent-1", Enabled: true, Secret: "agent-secret", Repositories: []string{"owner/repo"}})
	cfg, _ := broker.snapshot()
	statePath := filepath.Join(t.TempDir(), "shared-authority.db")
	cfg.PushTripwire = config.PushTripwireConfig{Enabled: true, ScannerID: "scanner", ScannerSecret: "scan-secret", StatePath: statePath, Repositories: map[string]config.PushTripwireRepository{"owner/repo": {BaseRef: "refs/heads/main", RefPatterns: []string{"^refs/heads/agent/.+$"}}}, ResponseProfiles: map[string]config.PushTripwireResponseProfile{"writer": {Generation: 1, AllowHalt: true}}, Bounds: config.PushTripwireBounds{MaxCommits: 10, MaxPaths: 10, MaxCommitMessageBytes: 1024, MaxBlobBytes: 1024, MaxTotalBytes: 8192}}
	store, err := pushtripwire.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	broker.tripwire = store
	body := map[string]interface{}{"version": pushtripwire.Version, "finding_id": "finding-registration", "delivery_id": "delivery-registration", "repository": "owner/repo", "ref": "refs/heads/agent/proof", "before": strings.Repeat("a", 40), "after": strings.Repeat("b", 40), "severity": "high", "reason_code": "seeded_canary_match", "profile": "writer", "profile_generation": 1, "actions": []string{"halt_issuance"}}
	headers := map[string]string{"Authorization": "Bearer scan-secret", "Idempotency-Key": "registration-proof"}
	resp := brokerRequestHeaders(t, broker, http.MethodPost, "/v1/security/push-tripwire/respond", body, headers)
	if resp.Code != http.StatusInternalServerError || strings.Contains(resp.Body.String(), `"state":"halted"`) {
		t.Fatalf("unregistered response=%d %s", resp.Code, resp.Body.String())
	}
	if err := store.ReplaceEnforcementCatalog(context.Background(), map[string]int64{"writer": 1}); err != nil {
		t.Fatal(err)
	}
	resp = brokerRequestHeaders(t, broker, http.MethodPost, "/v1/security/push-tripwire/respond", body, headers)
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `"state":"halted"`) {
		t.Fatalf("registered response=%d %s", resp.Code, resp.Body.String())
	}
}

func TestOpaqueGitReceivePackPolicyDeniesBeforeTokenOrUpstream(t *testing.T) {
	apiRequests, gitRequests := 0, 0
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiRequests++
		w.WriteHeader(http.StatusTeapot)
	}))
	defer apiServer.Close()
	gitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gitRequests++
		w.WriteHeader(http.StatusTeapot)
	}))
	defer gitServer.Close()
	broker := newTestBroker(t, apiServer.URL, gitServer.URL, config.Agent{
		ID:             "authority-worker",
		Enabled:        true,
		Secret:         "agent-secret",
		Repositories:   []string{"owner/repo"},
		Operations:     []string{"git.receive-pack"},
		BranchPatterns: []string{"^refs/heads/agent/authority-worker/.+$"},
		GitReceivePack: config.GitReceivePackDenyOpaque,
	})
	body := append(pktLine("0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/agent/authority-worker/test\x00 report-status\n"), []byte("0000")...)
	req := httptest.NewRequest(http.MethodPost, "/git/owner/repo.git/git-receive-pack", bytes.NewReader(body))
	req.SetBasicAuth("authority-worker", "agent-secret")
	resp := httptest.NewRecorder()
	broker.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden || !strings.Contains(resp.Body.String(), "semantic packfile inspection") {
		t.Fatalf("receive-pack denial = %d %q", resp.Code, resp.Body.String())
	}
	if apiRequests != 0 || gitRequests != 0 {
		t.Fatalf("denied receive-pack reached token/upstream: api=%d git=%d", apiRequests, gitRequests)
	}
}

func TestOpaquePushPreflightRejectsDeletionAndBeforeMismatch(t *testing.T) {
	for name, values := range map[string][3]string{
		"deletion": {strings.Repeat("a", 40), strings.Repeat("0", 40), "ref_deletion_rejected"},
		"mismatch": {strings.Repeat("a", 40), strings.Repeat("b", 40), "ref_before_mismatch"},
	} {
		t.Run(name, func(t *testing.T) {
			before, after, wantCode := values[0], values[1], values[2]
			gitRequests := 0
			apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
					writeTestJSON(t, w, map[string]string{"token": "fake-install-token", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)})
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/owner/repo/git/ref/"):
					writeTestJSON(t, w, map[string]interface{}{"object": map[string]string{"sha": strings.Repeat("c", 40)}})
				default:
					t.Fatalf("unexpected API request: %s %s", r.Method, r.URL.Path)
				}
			}))
			defer apiServer.Close()
			gitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gitRequests++; w.WriteHeader(http.StatusOK) }))
			defer gitServer.Close()
			broker := newTestBroker(t, apiServer.URL, gitServer.URL, config.Agent{ID: "agent-1", Enabled: true, Secret: "agent-secret", Repositories: []string{"owner/repo"}, Operations: []string{"git.receive-pack"}, BranchPatterns: []string{"^refs/heads/agent/agent-1/.+$"}})
			body := append(pktLine(before+" "+after+" refs/heads/agent/agent-1/test\x00 report-status\n"), []byte("0000")...)
			req := httptest.NewRequest(http.MethodPost, "/git/owner/repo.git/git-receive-pack", bytes.NewReader(body))
			req.SetBasicAuth("agent-1", "agent-secret")
			resp := httptest.NewRecorder()
			broker.ServeHTTP(resp, req)
			if resp.Code != http.StatusForbidden || !strings.Contains(resp.Body.String(), wantCode) {
				t.Fatalf("response=%d %s", resp.Code, resp.Body.String())
			}
			if gitRequests != 0 {
				t.Fatal("rejected update reached Git upstream")
			}
		})
	}
}

func TestMalformedReceivePackPrefixIsRejectedWithoutForwardingConsumedBytes(t *testing.T) {
	apiRequests, gitRequests := 0, 0
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { apiRequests++; w.WriteHeader(http.StatusTeapot) }))
	defer apiServer.Close()
	gitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gitRequests++; w.WriteHeader(http.StatusTeapot) }))
	defer gitServer.Close()
	broker := newTestBroker(t, apiServer.URL, gitServer.URL, config.Agent{ID: "agent-1", Enabled: true, Secret: "agent-secret", Repositories: []string{"owner/repo"}, Operations: []string{"git.receive-pack"}, BranchPatterns: []string{"^refs/heads/agent/agent-1/.+$"}})
	body := append(pktLine("not-a-valid-update\n"), []byte("0000PACK")...)
	req := httptest.NewRequest(http.MethodPost, "/git/owner/repo.git/git-receive-pack", bytes.NewReader(body))
	req.SetBasicAuth("agent-1", "agent-secret")
	resp := httptest.NewRecorder()
	broker.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if apiRequests != 0 || gitRequests != 0 {
		t.Fatalf("malformed prefix forwarded: api=%d git=%d", apiRequests, gitRequests)
	}
}

func TestGitHubReceivePackRejectionIsForwardedAndClassified(t *testing.T) {
	apiServer := fakeTokenServer(t)
	defer apiServer.Close()
	statusBody := append(pktLine("unpack ok\n"), pktLine("ng refs/heads/agent/agent-1/test protected branch\n")...)
	statusBody = append(statusBody, []byte("0000")...)
	gitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		if _, err := w.Write(statusBody); err != nil {
			t.Error(err)
		}
	}))
	defer gitServer.Close()
	broker := newTestBroker(t, apiServer.URL, gitServer.URL, config.Agent{ID: "agent-1", Enabled: true, Secret: "agent-secret", Repositories: []string{"owner/repo"}, Operations: []string{"git.receive-pack"}, BranchPatterns: []string{"^refs/heads/agent/agent-1/.+$"}})
	body := append(pktLine(strings.Repeat("0", 40)+" "+strings.Repeat("1", 40)+" refs/heads/agent/agent-1/test\x00 report-status\n"), []byte("0000")...)
	req := httptest.NewRequest(http.MethodPost, "/git/owner/repo.git/git-receive-pack", bytes.NewReader(body))
	req.SetBasicAuth("agent-1", "agent-secret")
	resp := httptest.NewRecorder()
	broker.ServeHTTP(resp, req)
	if !bytes.Equal(resp.Body.Bytes(), statusBody) {
		t.Fatalf("receive-pack response changed: %q", resp.Body.Bytes())
	}
	cfg, _ := broker.snapshot()
	auditBytes, err := os.ReadFile(cfg.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(auditBytes, []byte(`"result":"github_ref_update_rejected"`)) {
		t.Fatalf("stable rejection missing from audit: %s", auditBytes)
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
		Idempotency: config.IdempotencyConfig{
			StatePath: filepath.Join(t.TempDir(), "idempotency.json"),
		},
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
	broker, err := New("", cfg, gh, auditLog)
	if err != nil {
		t.Fatal(err)
	}
	return broker
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
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/owner/repo/git/ref/heads/") {
			requireBearer(t, r)
			w.WriteHeader(http.StatusNotFound)
			writeTestBody(t, w, `{"message":"Not Found"}`)
			return
		}
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
	return brokerRequestHeaders(t, broker, method, path, body, nil)
}

func brokerRequestHeaders(t *testing.T, broker *Server, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
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
	for key, value := range headers {
		req.Header.Set(key, value)
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

func readBrokerAuditEvents(t *testing.T, path string) []audit.Event {
	t.Helper()
	// #nosec G304 -- test helper reads the audit path created by the test broker.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	events := make([]audit.Event, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("decode audit line %q: %v", line, err)
		}
		events = append(events, ev)
	}
	return events
}

func lastAuditEventForOperation(t *testing.T, events []audit.Event, operation string) audit.Event {
	t.Helper()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Operation == operation {
			return events[i]
		}
	}
	t.Fatalf("audit operation %q missing from %+v", operation, events)
	return audit.Event{}
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
