package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gh-agent-broker/internal/auth"
	"gh-agent-broker/internal/config"
	"gh-agent-broker/internal/policy"
	"gh-agent-broker/internal/pushtripwire"
	"gh-agent-broker/internal/sandbox"
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

func TestGitOperationRejectsMalformedQueryShapes(t *testing.T) {
	for _, test := range []struct {
		method string
		target string
		suffix string
	}{
		{method: http.MethodGet, target: "/git/owner/repo.git/info/refs?service=git-upload-pack&%zz", suffix: "/info/refs"},
		{method: http.MethodGet, target: "/git/owner/repo.git/info/refs?service=git-receive-pack&%zz", suffix: "/info/refs"},
		{method: http.MethodPost, target: "/git/owner/repo.git/git-upload-pack?service=git-upload-pack", suffix: "/git-upload-pack"},
		{method: http.MethodPost, target: "/git/owner/repo.git/git-receive-pack?service=git-receive-pack", suffix: "/git-receive-pack"},
	} {
		t.Run(test.target, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.target, nil)
			if got := gitOperation(req, test.suffix); got != "" {
				t.Fatalf("gitOperation() = %q, want empty", got)
			}
		})
	}
}

func TestReceivePackUpdatesAndStableRejection(t *testing.T) {
	body := append(pktLine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/heads/agent/a\x00 report-status\n"), pktLine("cccccccccccccccccccccccccccccccccccccccc dddddddddddddddddddddddddddddddddddddddd refs/heads/agent/b\n")...)
	body = append(body, []byte("0000PACK")...)
	updates, err := receivePackUpdates(body)
	if err != nil || len(updates) != 2 || updates[1].Ref != "refs/heads/agent/b" {
		t.Fatalf("updates=%+v err=%v", updates, err)
	}
	result := append(pktLine("unpack ok\n"), pktLine("ng refs/heads/agent/a protected branch hook declined\n")...)
	result = append(result, []byte("0000")...)
	if !receivePackRejected(result) {
		t.Fatal("stable ng status was not classified")
	}
	if !receivePackRejected(pktLine("\x01ng refs/heads/agent/a protected branch\n")) {
		t.Fatal("sideband ng status was not classified")
	}
	if receivePackRejected([]byte("protected branch")) {
		t.Fatal("English prose was incorrectly classified")
	}
}

func TestReceivePackCommandPrefixLeavesLargeOpaquePackStreamUnread(t *testing.T) {
	command := append(pktLine(strings.Repeat("0", 40)+" "+strings.Repeat("1", 40)+" refs/heads/agent/large\x00 report-status\n"), []byte("0000")...)
	packSize := int64(32 << 20)
	body := io.MultiReader(bytes.NewReader(command), io.LimitReader(zeroReader{}, packSize))
	prefix, updates, err := readReceivePackCommandPrefix(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prefix, command) || len(updates) != 1 {
		t.Fatalf("prefix/updates mismatch: prefix=%d updates=%+v", len(prefix), updates)
	}
	remaining, err := io.Copy(io.Discard, body)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != packSize {
		t.Fatalf("remaining pack bytes=%d want=%d", remaining, packSize)
	}
}

func TestReceivePackCommandPrefixBound(t *testing.T) {
	base := strings.Repeat("0", 40) + " " + strings.Repeat("1", 40) + " refs/heads/agent/bound\x00"
	payload := base + strings.Repeat("x", 65531-len(base))
	packet := pktLine(payload)
	body := bytes.NewReader(append(append(append(append(append([]byte{}, packet...), packet...), packet...), packet...), packet...))
	if _, _, err := readReceivePackCommandPrefix(body); !errors.Is(err, errReceivePackCommandPrefixLimit) {
		t.Fatalf("prefix bound error=%v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestResponseScopeRejectsArbitraryProfileGenerationAndBinding(t *testing.T) {
	cfg := config.PushTripwireConfig{ResponseProfiles: map[string]config.PushTripwireResponseProfile{"curator": {Generation: 7, AllowHalt: true, AllowFence: true, Bindings: []config.PushTripwireBinding{{WorkerID: "worker", SessionLineageID: "session", WorkerStorageLineageID: "storage", WorkerFenceEpoch: 2}}}}}
	base := pushtripwire.ResponseRequest{Version: pushtripwire.Version, FindingID: "finding", Profile: "curator", ProfileGeneration: 7, Actions: []string{"halt_issuance"}}
	if !responseWithinReviewedScope(cfg, base) {
		t.Fatal("reviewed halt rejected")
	}
	base.Profile = "arbitrary"
	if responseWithinReviewedScope(cfg, base) {
		t.Fatal("arbitrary profile accepted")
	}
	base.Profile = "curator"
	base.ProfileGeneration = 8
	if responseWithinReviewedScope(cfg, base) {
		t.Fatal("stale generation accepted")
	}
	base.ProfileGeneration = 7
	base.Actions = []string{"fence_worker_session"}
	base.Binding = &pushtripwire.Binding{WorkerID: "other", SessionLineageID: "session", WorkerStorageLineageID: "storage", WorkerFenceEpoch: 2}
	if responseWithinReviewedScope(cfg, base) {
		t.Fatal("unbound worker accepted")
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

func TestRegisteredGreenPRCreateRejectsCallerFacts(t *testing.T) {
	for _, body := range []string{`{"title":"caller title"}`, `{"head":"agent/caller"}`, `{"base":"caller-base"}`, `{"body":"caller body"}`, `{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`} {
		t.Run(body, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/registered/github-green-pr/create", strings.NewReader(body))
			resp := httptest.NewRecorder()
			(&Server{}).ServeHTTP(resp, req)
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestGreenPRRequestUsesOnlyDurableAdmissionAndBrokerPush(t *testing.T) {
	admission := sandbox.GreenPRTransportAdmission{
		TaskDigest:  "sha256:durable-task",
		OperationID: "broker-push-operation",
		PushedSHA:   strings.Repeat("a", 40),
		Task: sandbox.RegisteredTask{Parameters: sandbox.RegisteredTaskParameters{
			Repository: "owner/durable-repository",
			BaseBranch: "durable-base",
			BranchRef:  "agent/fleiglabs-repo-agent/durable-work",
		}},
	}
	got := greenPRRequest(admission, "configured-app", 77)
	if got.Repository != admission.Task.Parameters.Repository || got.BaseRef != admission.Task.Parameters.BaseBranch || got.WorkerRef != "refs/heads/"+admission.Task.Parameters.BranchRef || got.PushedHeadSHA != admission.PushedSHA || got.BrokerOperationID != admission.OperationID || got.RegisteredTaskDigest != admission.TaskDigest || got.AppSlug != "configured-app" || got.InstallationID != 77 {
		t.Fatalf("green PR request was not fully broker-derived: %#v", got)
	}
}

func TestRegisteredGreenPRPolicyCheckRequiresExactEndpointOperations(t *testing.T) {
	admission := sandbox.GreenPRTransportAdmission{Task: sandbox.RegisteredTask{Parameters: sandbox.RegisteredTaskParameters{
		Repository: "owner/repo",
		BaseBranch: "main",
		BranchRef:  "agent/writer/work",
	}}}
	principal := func(operations ...string) auth.Principal {
		agent := config.Agent{
			ID:             "writer",
			Enabled:        true,
			Repositories:   []string{"owner/repo"},
			Operations:     operations,
			BaseBranches:   []string{"main"},
			BranchPatterns: []string{"^agent/writer/.+$"},
		}
		return auth.Principal{ID: agent.ID, Agent: agent}
	}

	if result := registeredGreenPRPolicyCheck(principal("repo.probe", "pull.read", "pull.create"), admission, "creation"); !result.Allowed {
		t.Fatalf("creation unexpectedly denied: %#v", result)
	}
	if result := registeredGreenPRPolicyCheck(principal("repo.probe", "pull.read", "checks.read", "status.read"), admission, "observation"); !result.Allowed {
		t.Fatalf("observation unexpectedly denied: %#v", result)
	}
	for _, missing := range []string{"repo.probe", "pull.read", "checks.read", "status.read"} {
		t.Run("missing_"+missing, func(t *testing.T) {
			operations := []string{"repo.probe", "pull.read", "checks.read", "status.read"}
			for i, operation := range operations {
				if operation == missing {
					operations = append(operations[:i], operations[i+1:]...)
					break
				}
			}
			result := registeredGreenPRPolicyCheck(principal(operations...), admission, "observation")
			if result.Allowed || result.Decision != policy.DecisionDeny {
				t.Fatalf("observation allowed without %q: %#v", missing, result)
			}
			if len(result.FailedChecks) != 1 || result.FailedChecks[0].Dimension != "operation" || result.FailedChecks[0].Actual != missing {
				t.Fatalf("denial did not identify missing %q authorization: %#v", missing, result)
			}
		})
	}
	for _, missing := range []string{"repo.probe", "pull.read", "pull.create"} {
		t.Run("creation_missing_"+missing, func(t *testing.T) {
			operations := []string{"repo.probe", "pull.read", "pull.create"}
			for i, operation := range operations {
				if operation == missing {
					operations = append(operations[:i], operations[i+1:]...)
					break
				}
			}
			if result := registeredGreenPRPolicyCheck(principal(operations...), admission, "creation"); result.Allowed {
				t.Fatalf("creation allowed without %q", missing)
			}
		})
	}
}

func TestConfiguredTransportAgentFailsClosedOnInvalidMapping(t *testing.T) {
	authority := sandbox.TransportAuthority{Principal: "authority-worker-operator", Profile: "general-writer-v1"}
	enabled := config.Agent{ID: "fleiglabs-repo-agent", Enabled: true}
	disabled := config.Agent{ID: "disabled-agent", Enabled: false}
	tests := []struct {
		name     string
		mappings map[string]string
		agents   []config.Agent
		wantID   string
	}{
		{name: "mapped enabled agent", mappings: map[string]string{"general-writer-v1": enabled.ID}, agents: []config.Agent{enabled}, wantID: enabled.ID},
		{name: "missing mapping", mappings: nil, agents: []config.Agent{enabled}},
		{name: "different profile mapping", mappings: map[string]string{"other-profile": enabled.ID}, agents: []config.Agent{enabled}},
		{name: "empty mapping", mappings: map[string]string{"general-writer-v1": ""}, agents: []config.Agent{enabled}},
		{name: "whitespace mapping", mappings: map[string]string{"general-writer-v1": " fleiglabs-repo-agent"}, agents: []config.Agent{enabled}},
		{name: "unknown mapped agent", mappings: map[string]string{"general-writer-v1": "unknown-agent"}, agents: []config.Agent{enabled}},
		{name: "disabled mapped agent", mappings: map[string]string{"general-writer-v1": disabled.ID}, agents: []config.Agent{disabled}},
		{name: "stale configured-agent mismatch", mappings: map[string]string{"general-writer-v1": enabled.ID}, agents: []config.Agent{{ID: "replacement-agent", Enabled: true}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broker := &Server{transportProfiles: test.mappings}
			agent, ok := broker.configuredTransportAgent(&config.Config{Agents: test.agents}, authority)
			if test.wantID == "" {
				if ok || agent.ID != "" {
					t.Fatalf("invalid mapping resolved agent %#v", agent)
				}
				return
			}
			if !ok || agent.ID != test.wantID {
				t.Fatalf("mapped agent = %#v, ok=%v, want %q", agent, ok, test.wantID)
			}
		})
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
