package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gh-agent-broker/internal/api"
	"gh-agent-broker/internal/config"
	"gh-agent-broker/internal/idempotency"
)

func TestAggregateCIUsesActiveRuleIdentities(t *testing.T) {
	appID := int64(42)
	rules := &api.BranchRules{Rules: []api.BranchRule{{Type: "required_status_checks", Parameters: api.BranchRuleParameters{RequiredStatusChecks: []api.RequiredStatusCheck{{Context: "unit", IntegrationID: &appID}, {Context: "integration"}}}}}}
	required := requiredCI(rules, nil)
	if len(required) != 2 || aggregateCI(required, api.CommitStatus{}, api.CheckRuns{CheckRuns: []api.CheckRun{{Name: "unit", Status: "completed", Conclusion: "success", App: &api.CheckApp{ID: appID}}, {Name: "integration", Status: "completed", Conclusion: "failure"}}}, nil) != "code_failure" {
		t.Fatalf("required CI aggregation did not use active rules: %#v", required)
	}
	if got := aggregateCI(required, api.CommitStatus{Statuses: []api.StatusContext{{Context: "unit", State: "success"}}}, api.CheckRuns{}, nil); got != "pending" {
		t.Fatalf("missing required check = %q, want pending", got)
	}
}

func TestAggregateCIRequiredCheckStatesAndLegacyProtection(t *testing.T) {
	legacy := &api.BranchProtection{RequiredStatusChecks: &api.LegacyRequiredStatusChecks{Contexts: []string{"legacy"}, Checks: []api.RequiredStatusCheck{{Context: "check"}}}}
	required := requiredCI(nil, legacy)
	if got := aggregateCI(required, api.CommitStatus{Statuses: []api.StatusContext{{Context: "legacy", State: "success"}}}, api.CheckRuns{CheckRuns: []api.CheckRun{{Name: "check", Status: "completed", Conclusion: "success"}}}, nil); got != "success" {
		t.Fatalf("success=%q", got)
	}
	if got := aggregateCI(required, api.CommitStatus{}, api.CheckRuns{}, nil); got != "pending" {
		t.Fatalf("missing=%q", got)
	}
	if got := aggregateCI(required, api.CommitStatus{Statuses: []api.StatusContext{{Context: "legacy", State: "pending"}}}, api.CheckRuns{}, nil); got != "pending" {
		t.Fatalf("pending=%q", got)
	}
	if got := aggregateCI(required, api.CommitStatus{Statuses: []api.StatusContext{{Context: "legacy", State: "error"}}}, api.CheckRuns{}, nil); got != "infrastructure_failure" {
		t.Fatalf("infra=%q", got)
	}
	if got := aggregateCI(required, api.CommitStatus{Statuses: []api.StatusContext{{Context: "legacy", State: "failure"}}}, api.CheckRuns{}, nil); got != "code_failure" {
		t.Fatalf("code=%q", got)
	}
	if got := aggregateCI(nil, api.CommitStatus{}, api.CheckRuns{}, nil); got != "success" {
		t.Fatalf("no requirements=%q", got)
	}
}

func TestAggregateCIUnboundChecksAcceptStatusAndRequiredWorkflows(t *testing.T) {
	rules := &api.BranchRules{Rules: []api.BranchRule{
		{Type: "required_status_checks", Parameters: api.BranchRuleParameters{RequiredStatusChecks: []api.RequiredStatusCheck{{Context: "build"}}}},
		{Type: "required_workflows", Parameters: api.BranchRuleParameters{RequiredWorkflows: []api.RequiredWorkflow{{Path: ".github/workflows/verify.yml", Ref: "main", RepositoryID: 1, SHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}},
	}}
	required := requiredCI(rules, nil)
	if len(required) != 2 {
		t.Fatalf("required=%#v", required)
	}
	// Mirrors GitHub's workflow-run response: the referenced path carries an
	// @ref suffix and the object does not include repository_id.
	workflow := api.ReferencedWorkflow{Path: "owner/repo/.github/workflows/verify.yml@main", SHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if got := aggregateCI(required, api.CommitStatus{Statuses: []api.StatusContext{{Context: "build", State: "success"}}}, api.CheckRuns{}, []api.WorkflowRun{{Status: "completed", Conclusion: "success", ReferencedWorkflows: []api.ReferencedWorkflow{workflow}}}); got != "success" {
		t.Fatalf("success=%q", got)
	}
	if got := aggregateCI(required, api.CommitStatus{}, api.CheckRuns{}, []api.WorkflowRun{{Status: "completed", Conclusion: "failure", ReferencedWorkflows: []api.ReferencedWorkflow{workflow}}}); got != "code_failure" {
		t.Fatalf("failure=%q", got)
	}
	if got := aggregateCI(required, api.CommitStatus{Statuses: []api.StatusContext{{Context: "build", State: "success"}}}, api.CheckRuns{}, nil); got != "pending" {
		t.Fatalf("missing workflow=%q", got)
	}
}

func TestWorkflowRunMatchingFailsClosedForPinnedDefinitionSHA(t *testing.T) {
	required := &api.RequiredWorkflow{Path: ".github/workflows/verify.yml", Ref: "main", SHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if workflowRunMatches(required, ".github/workflows/verify.yml@main", "", 0, "") {
		t.Fatal("direct workflow run without definition SHA satisfied SHA-pinned requirement")
	}
	if workflowRunMatches(required, "owner/repo/.github/workflows/verify.yml@main", "main", 0, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatal("wrong definition SHA satisfied SHA-pinned requirement")
	}
	if !workflowRunMatches(required, "owner/repo/.github/workflows/verify.yml@main", "main", 0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("matching referenced workflow did not satisfy SHA-pinned requirement")
	}
}

func TestReconcilePendingCommentFailsClosedOnAmbiguityAndIgnoresOldMatches(t *testing.T) {
	reserved := time.Now().UTC()
	body := "public body only"
	old := reserved.Add(-3 * time.Minute).Format(time.RFC3339)
	newer := reserved.Add(time.Second).Format(time.RFC3339)
	if got, ok, err := reconcilePendingComment([]api.IssueComment{{ID: 1, Body: body, Author: "human", CreatedAt: old}}, body, reserved); err != nil || ok || got.ID != 0 {
		t.Fatalf("old identical comment = %#v, %v, %v", got, ok, err)
	}
	if got, ok, err := reconcilePendingComment([]api.IssueComment{{ID: 2, Body: body, Author: "app", CreatedAt: newer}}, body, reserved); err != nil || !ok || got.ID != 2 {
		t.Fatalf("unique new comment = %#v, %v, %v", got, ok, err)
	}
	if got, ok, err := reconcilePendingComment([]api.IssueComment{{ID: 2, Body: body, Author: "app", CreatedAt: newer}, {ID: 3, Body: body, Author: "app", CreatedAt: newer}}, body, reserved); err == nil || ok || got.ID != 0 {
		t.Fatalf("ambiguous comment = %#v, %v, %v", got, ok, err)
	}
}

func TestExactCommentIdempotencyReplaysOnlySameDigestAcrossReload(t *testing.T) {
	cfg := config.IdempotencyConfig{StatePath: filepath.Join(t.TempDir(), "idempotency.json")}
	key, digest := "issue.comment:agent:owner/repo:7:key", "digest-a"
	if err := idempotency.Store(cfg, key, idempotency.Record{Operation: "issue.comment", RequestDigest: digest, Status: http.StatusCreated, Body: []byte(`{"id":9}`)}); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	replayed, conflict, err := replayExactIdempotent(recorder, cfg, key, "issue.comment", digest)
	if err != nil || !replayed || conflict || recorder.Code != http.StatusCreated {
		t.Fatalf("same request did not replay: replay=%v conflict=%v err=%v", replayed, conflict, err)
	}
	replayed, conflict, err = replayExactIdempotent(httptest.NewRecorder(), cfg, key, "issue.comment", "digest-b")
	if err != nil || replayed || !conflict {
		t.Fatalf("different request reused key: replay=%v conflict=%v err=%v", replayed, conflict, err)
	}
}

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

func TestReadReceivePackCommandPrefixAllowsLeadingShallowLines(t *testing.T) {
	const (
		oldOID     = "0000000000000000000000000000000000000000"
		newOID     = "1111111111111111111111111111111111111111"
		shallowOID = "0e1718a4281405e68902338962ca32e9ce527fff"
	)
	command := oldOID + " " + newOID + " refs/heads/curator/test\x00 report-status side-band-64k\n"
	packData := []byte("PACK\x00\x00\x00\x02")

	tests := []struct {
		name     string
		shallows []string
	}{
		{name: "one shallow line", shallows: []string{shallowOID}},
		{name: "multiple shallow lines", shallows: []string{shallowOID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{name: "no shallow lines"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantPrefix := make([]byte, 0)
			for _, oid := range tt.shallows {
				wantPrefix = append(wantPrefix, pktLine("shallow "+oid+"\n")...)
			}
			wantPrefix = append(wantPrefix, pktLine(command)...)
			wantPrefix = append(wantPrefix, []byte("0000")...)
			body := append(append([]byte{}, wantPrefix...), packData...)

			bodyReader := bytes.NewReader(body)
			prefix, updates, err := readReceivePackCommandPrefix(bodyReader)
			if err != nil {
				t.Fatalf("readReceivePackCommandPrefix() error = %v", err)
			}
			if !bytes.Equal(prefix, wantPrefix) {
				t.Fatalf("prefix = %x, want %x", prefix, wantPrefix)
			}
			if len(updates) != 1 || updates[0].Ref != "refs/heads/curator/test" {
				t.Fatalf("updates = %+v, want curator branch update", updates)
			}
			forwarded, err := io.ReadAll(io.MultiReader(bytes.NewReader(prefix), bodyReader))
			if err != nil {
				t.Fatalf("read reconstructed body: %v", err)
			}
			if !bytes.Equal(forwarded, body) {
				t.Fatalf("reconstructed body = %x, want byte-identical %x", forwarded, body)
			}
		})
	}
}

func TestReadReceivePackCommandPrefixFailureReasons(t *testing.T) {
	validUpdate := "0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/curator/test\n"
	boundPayload := validUpdate + strings.Repeat(" ", 65531-len(validUpdate))
	boundBody := make([]byte, 0, (4+len(boundPayload))*4+4)
	for range 4 {
		boundBody = append(boundBody, []byte("ffff")...)
		boundBody = append(boundBody, boundPayload...)
	}
	boundBody = append(boundBody, []byte("ffff")...)
	tooManyUpdates := make([]byte, 0, 65*(4+len(validUpdate)))
	for range 65 {
		tooManyUpdates = append(tooManyUpdates, pktLine(validUpdate)...)
	}
	type failureCase struct {
		name   string
		body   []byte
		reason string
	}
	tests := make([]failureCase, 0, 10)
	tests = append(tests,
		failureCase{name: "short read", body: []byte("00"), reason: receivePackPrefixFailureShortRead},
		failureCase{name: "bad pkt-line length", body: []byte("0003"), reason: receivePackPrefixFailureBadPktLineLength},
		failureCase{name: "non-hex length", body: []byte("zzzz"), reason: receivePackPrefixFailureNonHexLength},
		failureCase{name: "zero updates", body: []byte("0000"), reason: receivePackPrefixFailureZeroUpdates},
		failureCase{name: "malformed SHA", body: append(pktLine("not-a-sha 1111111111111111111111111111111111111111 refs/heads/curator/test\n"), []byte("0000")...), reason: receivePackPrefixFailureMalformedSHA},
		failureCase{name: "malformed ref name", body: append(pktLine("0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/tags/v1\n"), []byte("0000")...), reason: receivePackPrefixFailureMalformedRefName},
		failureCase{name: "exceeded bound", body: boundBody, reason: receivePackPrefixFailureExceededBound},
		failureCase{name: "malformed update", body: append(pktLine("only-two fields\n"), []byte("0000")...), reason: receivePackPrefixFailureMalformedUpdate},
		failureCase{name: "malformed shallow", body: append(pktLine("shallow not-a-sha\n"), []byte("0000")...), reason: receivePackPrefixFailureMalformedShallow},
		failureCase{name: "too many updates", body: tooManyUpdates, reason: receivePackPrefixFailureTooManyUpdates},
	)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := readReceivePackCommandPrefix(bytes.NewReader(tt.body))
			if err == nil {
				t.Fatal("readReceivePackCommandPrefix() error = nil")
			}
			var parseErr *receivePackPrefixParseError
			if !errors.As(err, &parseErr) {
				t.Fatalf("error = %T %v, want receivePackPrefixParseError", err, err)
			}
			if parseErr.reason != tt.reason {
				t.Fatalf("reason = %q, want %q", parseErr.reason, tt.reason)
			}
		})
	}
}

func TestReadReceivePackCommandPrefixTracksPartialRead(t *testing.T) {
	prefix, _, err := readReceivePackCommandPrefix(bytes.NewReader([]byte("00")))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want unexpected EOF", err)
	}
	if got := len(prefix); got != 2 {
		t.Fatalf("prefix bytes read = %d, want 2", got)
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
		"repo.probe":                 "GET /v1/repos/{owner}/{repo}/probe",
		"pull.create":                "POST /v1/repos/{owner}/{repo}/pulls",
		"pull.review.dismiss":        "PUT /v1/repos/{owner}/{repo}/pulls/{number}/reviews/{review_id}/dismissal",
		"pull.review_thread.resolve": "PUT /v1/repos/{owner}/{repo}/pulls/{number}/review-threads/{thread_id}/resolve",
		"issue.create":               "POST /v1/repos/{owner}/{repo}/issues",
		"issue.comment":              "POST /v1/repos/{owner}/{repo}/issues/{number}/comments",
		"issue.label.add":            "POST /v1/repos/{owner}/{repo}/issues/{number}/labels",
		"issue.label.remove":         "DELETE /v1/repos/{owner}/{repo}/issues/{number}/labels/{label}",
		"policy.dry-run":             "POST /v1/policy/dry-run",
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

func TestUnauthorizedResponsesIncludeBasicChallenge(t *testing.T) {
	srv := &Server{cfg: &config.Config{}}
	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodGet, path: "/whoami"},
		{method: http.MethodPost, path: "/v1/policy/dry-run", body: `{}`},
		{method: http.MethodGet, path: "/git/owner/repo.git/info/refs?service=git-upload-pack"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		resp := httptest.NewRecorder()
		srv.ServeHTTP(resp, req)
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status = %d, want %d", tc.method, tc.path, resp.Code, http.StatusUnauthorized)
		}
		if got := resp.Header().Get("WWW-Authenticate"); got != `Basic realm="gh-agent-broker"` {
			t.Fatalf("%s %s WWW-Authenticate = %q", tc.method, tc.path, got)
		}
	}
}

func TestDryRunAcceptsRepositoryAliasesAndBrokerInjectedMetadata(t *testing.T) {
	srv := &Server{cfg: &config.Config{
		GitHub: config.GitHubConfig{Installations: map[string]int64{"owner/repo": 42}},
		Agents: []config.Agent{{
			ID:           "agent-1",
			Enabled:      true,
			Secret:       "secret",
			Repositories: []string{"owner/repo"},
			Operations:   []string{"pull.create"},
			BaseBranches: []string{"main"},
			MetadataAssertions: map[string]config.AssertionPolicy{
				"pull.create": {
					Mode: "enforce",
					Fields: []config.AssertionField{
						{Name: "Agent-Id", Required: true, Value: "agent-1", Locations: []string{"request", "pr_body"}},
						{Name: "Hermes-Run-Id", Required: true, Pattern: "^[A-Za-z0-9_.:-]+$", Locations: []string{"request", "pr_body"}},
						{Name: "Broker-Operation-Id", Required: true, Locations: []string{"pr_body"}},
						{Name: "GitHub-App-Installation-Id", Required: true, Locations: []string{"pr_body"}},
					},
				},
			},
		}},
	}}
	bodies := []string{
		`{"repo":"owner/repo","operation":"pull.create","base_branch":"main","metadata":{"Agent-Id":"agent-1","Hermes-Run-Id":"run-1"}}`,
		`{"repository":"owner/repo","operation":"pull.create","base_branch":"main","metadata":{"Agent-Id":"agent-1","Hermes-Run-Id":"run-1"}}`,
		`{"owner":"owner","repo":"repo","operation":"pull.create","base_branch":"main","metadata":{"Agent-Id":"agent-1","Hermes-Run-Id":"run-1"}}`,
	}
	for _, body := range bodies {
		req := httptest.NewRequest(http.MethodPost, "/v1/policy/dry-run", bytes.NewBufferString(body))
		req.SetBasicAuth("agent-1", "secret")
		resp := httptest.NewRecorder()
		srv.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("dry-run status = %d, want %d; body=%s", resp.Code, http.StatusOK, resp.Body.String())
		}
		var out map[string]interface{}
		if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out["allowed"] != true {
			t.Fatalf("dry-run allowed = %v; body=%s", out["allowed"], resp.Body.String())
		}
	}
}

func TestOpenAPIIncludesRequestSchemas(t *testing.T) {
	resp := httptest.NewRecorder()
	(&Server{}).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	components := objectAt(t, out, "components")
	schemas := objectAt(t, components, "schemas")
	for _, name := range []string{"DryRunRequest", "DryRunResponse", "PullCreateRequest", "CommentCreateRequest", "IssueLabelsRequest", "PullReviewDismissRequest", "PullReviewThreadResolveRequest", "ErrorResponse"} {
		if _, ok := schemas[name]; !ok {
			t.Fatalf("missing schema %s", name)
		}
	}
	paths := objectAt(t, out, "paths")
	pulls := objectAt(t, paths, "/v1/repos/{owner}/{repo}/pulls")
	post := objectAt(t, pulls, "post")
	if _, ok := post["requestBody"]; !ok {
		t.Fatalf("pull.create missing requestBody")
	}
	dismissal := objectAt(t, paths, "/v1/repos/{owner}/{repo}/pulls/{number}/reviews/{review_id}/dismissal")
	put := objectAt(t, dismissal, "put")
	if _, ok := put["requestBody"]; !ok {
		t.Fatalf("pull.review.dismiss missing requestBody")
	}
	resolve := objectAt(t, paths, "/v1/repos/{owner}/{repo}/pulls/{number}/review-threads/{thread_id}/resolve")
	put = objectAt(t, resolve, "put")
	if _, ok := put["requestBody"]; !ok {
		t.Fatalf("pull.review_thread.resolve missing requestBody")
	}
	labels := objectAt(t, paths, "/v1/repos/{owner}/{repo}/issues/{number}/labels")
	post = objectAt(t, labels, "post")
	if _, ok := post["requestBody"]; !ok {
		t.Fatalf("issue.label.add missing requestBody")
	}
	labelRemove := objectAt(t, paths, "/v1/repos/{owner}/{repo}/issues/{number}/labels/{label}")
	if _, ok := labelRemove["delete"]; !ok {
		t.Fatalf("issue.label.remove missing delete operation")
	}
}

func objectAt(t *testing.T, m map[string]interface{}, key string) map[string]interface{} {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	out, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("key %q is %T, want object", key, v)
	}
	return out
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
