package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRESTLaunchProfileAuthzAndLaunch(t *testing.T) {
	cfg := restTestConfig(t)
	runtime := newFakeRuntime()
	service := newRESTTestService(t, cfg, runtime, testAudit(t))
	handler := NewRESTHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/v1/launch-profiles/nightly/launch", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want 401", resp.Code)
	}

	req = restLaunchRequest("/v1/launch-profiles/nightly/launch", "timer-secret", "launch-1", nil)
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("launch status = %d body=%s", resp.Code, resp.Body.String())
	}
	var out LaunchAgentOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.RunID == "" || out.Status != StatusRunning {
		t.Fatalf("launch output = %+v", out)
	}
	if spec := runtime.lastSpec(); spec.RunID != out.RunID || spec.Env["SANDBOX_REPO"] != "owner/repo" {
		t.Fatalf("runtime spec = %+v", spec)
	}

	req = restRequest(http.MethodGet, "/v1/runs/"+out.RunID+"/logs", "timer-secret", nil)
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("timer logs status = %d, want 403", resp.Code)
	}

	runtime.logs = "Authorization: Bearer secret-value\n"
	req = restRequest(http.MethodGet, "/v1/runs/"+out.RunID+"/logs?max_bytes=1024", "operator-secret", nil)
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("operator logs status = %d body=%s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "secret-value") {
		t.Fatalf("logs response leaked secret: %s", resp.Body.String())
	}
}

func TestRESTOptionalIdempotencyDoesNotBreakUnrelatedProfile(t *testing.T) {
	cfg := restTestConfig(t)
	profile := cfg.LaunchProfiles["nightly"]
	profile.RequireIdempotencyKey = false
	cfg.LaunchProfiles["nightly"] = profile
	runtime := newFakeRuntime()
	handler := NewRESTHandler(newRESTTestService(t, cfg, runtime, testAudit(t)))

	for range 2 {
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, restRequest(http.MethodPost, "/v1/launch-profiles/nightly/launch", "timer-secret", nil))
		if resp.Code != http.StatusOK {
			t.Fatalf("optional idempotency launch status=%d body=%s", resp.Code, resp.Body.String())
		}
	}
	if len(runtime.specs) != 2 {
		t.Fatalf("runtime creates=%d, want 2 independent launches", len(runtime.specs))
	}
}

func TestRESTOwnedRunScopeAndProfileRecoveryScope(t *testing.T) {
	cfg := restTestConfig(t)
	cfg.OperatorPrincipals["timer"] = OperatorPrincipal{
		Token: "timer-secret", AllowedProfiles: []string{"nightly"}, AllowedActions: []string{"launch", "status"}, RunScope: "owned",
	}
	cfg.OperatorPrincipals["peer"] = OperatorPrincipal{
		Token: "peer-secret", AllowedProfiles: []string{"nightly"}, AllowedActions: []string{"launch", "status"}, RunScope: "owned",
	}
	handler := NewRESTHandler(newRESTTestService(t, cfg, newFakeRuntime(), testAudit(t)))
	timerRun := performLaunch(t, handler, "owned-key", nil)

	peerList := httptest.NewRecorder()
	handler.ServeHTTP(peerList, restRequest(http.MethodGet, "/v1/runs", "peer-secret", nil))
	if peerList.Code != http.StatusOK || strings.Contains(peerList.Body.String(), timerRun.RunID) {
		t.Fatalf("peer list status=%d body=%s", peerList.Code, peerList.Body.String())
	}
	peerRead := httptest.NewRecorder()
	handler.ServeHTTP(peerRead, restRequest(http.MethodGet, "/v1/runs/"+timerRun.RunID, "peer-secret", nil))
	if peerRead.Code != http.StatusNotFound || !strings.Contains(peerRead.Body.String(), `"code":"not_found"`) {
		t.Fatalf("peer read status=%d body=%s", peerRead.Code, peerRead.Body.String())
	}

	adminList := httptest.NewRecorder()
	handler.ServeHTTP(adminList, restRequest(http.MethodGet, "/v1/runs", "operator-secret", nil))
	if adminList.Code != http.StatusOK || !strings.Contains(adminList.Body.String(), timerRun.RunID) {
		t.Fatalf("admin list status=%d body=%s", adminList.Code, adminList.Body.String())
	}
	adminRead := httptest.NewRecorder()
	handler.ServeHTTP(adminRead, restRequest(http.MethodGet, "/v1/runs/"+timerRun.RunID, "operator-secret", nil))
	if adminRead.Code != http.StatusOK {
		t.Fatalf("admin read status=%d body=%s", adminRead.Code, adminRead.Body.String())
	}
}

func TestRESTDryRunAndOverridePolicy(t *testing.T) {
	cfg := restTestConfig(t)
	runtime := newFakeRuntime()
	service := newRESTTestService(t, cfg, runtime, testAudit(t))
	handler := NewRESTHandler(service)

	body := []byte(`{"overrides":{"task":"override task","repo":"owner/other"}}`)
	req := restRequest(http.MethodPost, "/v1/launch-profiles/nightly/dry-run", "timer-secret", body)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("disallowed override status = %d body=%s", resp.Code, resp.Body.String())
	}
	if len(runtime.specs) != 0 {
		t.Fatalf("dry-run override rejection created runtime specs")
	}

	body = []byte(`{"overrides":{"task":"override task","max_runtime_minutes":3}}`)
	req = restRequest(http.MethodPost, "/v1/launch-profiles/nightly/dry-run", "timer-secret", body)
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("dry-run status = %d body=%s", resp.Code, resp.Body.String())
	}
	if len(runtime.specs) != 0 {
		t.Fatalf("dry-run created runtime specs")
	}
	if entries, err := os.ReadDir(cfg.RunsDir); err == nil && len(entries) != 0 {
		t.Fatalf("dry-run created run dir entries: %+v", entries)
	}
}

func TestRESTLaunchProfileEnforcesConcurrencyLimit(t *testing.T) {
	cfg := restTestConfig(t)
	profile := testLaunchProfile()
	profile.MaxConcurrentRuns = 1
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": profile}
	runtime := newFakeRuntime()
	service := newRESTTestService(t, cfg, runtime, testAudit(t))
	handler := NewRESTHandler(service)

	first := restLaunchRequest("/v1/launch-profiles/nightly/launch", "timer-secret", "capacity-1", nil)
	firstResponse := httptest.NewRecorder()
	handler.ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("first launch status = %d body=%s", firstResponse.Code, firstResponse.Body.String())
	}
	service = newRESTTestService(t, cfg, runtime, testAudit(t))
	if err := service.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	handler = NewRESTHandler(service)

	second := restLaunchRequest("/v1/launch-profiles/nightly/launch", "timer-secret", "capacity-2", nil)
	secondResponse := httptest.NewRecorder()
	handler.ServeHTTP(secondResponse, second)
	if secondResponse.Code != http.StatusConflict || !strings.Contains(secondResponse.Body.String(), `"code":"profile_busy"`) {
		t.Fatalf("second launch status = %d body=%s", secondResponse.Code, secondResponse.Body.String())
	}
}

func TestRESTParameterizedPreviewAndLaunch(t *testing.T) {
	cfg := restTestConfig(t)
	profile := testLaunchProfile()
	profile.Parameters = map[string]ParameterDeclaration{
		"upload_ids": {
			Type:      "string_list",
			Required:  true,
			MaxItems:  2,
			MaxLength: 24,
			Pattern:   `^[A-Za-z0-9_.:-]+$`,
		},
	}
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": profile}
	runtime := newFakeRuntime()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	service := newRESTTestService(t, cfg, runtime, auditLog)
	handler := NewRESTHandler(service)

	body := []byte(`{"parameters":{"upload_ids":["upl_123","upl_456"]}}`)
	req := restRequest(http.MethodPost, "/v1/launch-profiles/nightly/preview", "timer-secret", body)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("preview status = %d body=%s", resp.Code, resp.Body.String())
	}
	if len(runtime.specs) != 0 {
		t.Fatalf("preview created runtime specs")
	}
	if entries, err := os.ReadDir(cfg.RunsDir); err == nil && len(entries) != 0 {
		t.Fatalf("preview created run dir entries: %+v", entries)
	}
	var preview LaunchPreviewOutput
	if err := json.NewDecoder(resp.Body).Decode(&preview); err != nil {
		t.Fatal(err)
	}
	gotUploads, ok := preview.TaskContract.Parameters["upload_ids"].([]any)
	if !ok || len(gotUploads) != 2 || gotUploads[0] != "upl_123" {
		t.Fatalf("preview parameters = %#v", preview.TaskContract.Parameters)
	}
	if preview.Template.Image == "" || preview.Budgets.RuntimeSeconds == 0 || preview.ConfigVersion == "" || preview.ConfigLoadedAt.IsZero() {
		t.Fatalf("incomplete preview = %+v", preview)
	}

	req = restLaunchRequest("/v1/launch-profiles/nightly/launch", "timer-secret", "parameters-1", body)
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("launch status = %d body=%s", resp.Code, resp.Body.String())
	}
	var launched LaunchAgentOutput
	if err := json.NewDecoder(resp.Body).Decode(&launched); err != nil {
		t.Fatal(err)
	}
	taskBytes, err := os.ReadFile(filepath.Join(cfg.RunsDir, launched.RunID, "input", "task.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract TaskContract
	if err := json.Unmarshal(taskBytes, &contract); err != nil {
		t.Fatal(err)
	}
	uploads, ok := contract.Parameters["upload_ids"].([]any)
	if !ok {
		t.Fatalf("task contract parameters = %#v", contract.Parameters)
	}
	if len(uploads) != 2 || uploads[1] != "upl_456" {
		t.Fatalf("task contract parameters = %#v", contract.Parameters)
	}

	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G304: auditPath is generated inside this test's temp directory.
	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(auditBytes), `"parameters":{"upload_ids":["upl_123","upl_456"]}`) {
		t.Fatalf("audit did not record sanitized parameters: %s", auditBytes)
	}
}

func TestRESTParameterizedLaunchRejectsInvalidParametersBeforeRunCreation(t *testing.T) {
	cfg := restTestConfig(t)
	profile := testLaunchProfile()
	profile.Parameters = map[string]ParameterDeclaration{
		"upload_ids": {Type: "string_list", Required: true, MaxItems: 1, MaxLength: 8, Pattern: `^[A-Za-z0-9_]+$`},
	}
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": profile}
	runtime := newFakeRuntime()
	service := newRESTTestService(t, cfg, runtime, testAudit(t))
	handler := NewRESTHandler(service)

	body := []byte(`{"parameters":{"upload_ids":["valid","too_many"]}}`)
	req := restLaunchRequest("/v1/launch-profiles/nightly/launch", "timer-secret", "invalid-parameters", body)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("invalid parameters status = %d body=%s", resp.Code, resp.Body.String())
	}
	if len(runtime.specs) != 0 {
		t.Fatalf("invalid parameters created runtime specs")
	}
	if entries, err := os.ReadDir(cfg.RunsDir); err == nil && len(entries) != 0 {
		t.Fatalf("invalid parameters created run dir entries: %+v", entries)
	}

	body = []byte(`{"parameters":{"upload_ids":["valid"]},"repo":"owner/other"}`)
	req = restRequest(http.MethodPost, "/v1/launch-profiles/nightly/preview", "timer-secret", body)
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "only parameters") {
		t.Fatalf("unexpected top-level field status = %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestRESTRunCollectionsReuseServiceProtections(t *testing.T) {
	cfg := restTestConfig(t)
	service := newRESTTestService(t, cfg, newFakeRuntime(), testAudit(t))
	handler := NewRESTHandler(service)

	launchReq := restLaunchRequest("/v1/launch-profiles/nightly/launch", "operator-secret", "collections-1", nil)
	launchResp := httptest.NewRecorder()
	handler.ServeHTTP(launchResp, launchReq)
	if launchResp.Code != http.StatusOK {
		t.Fatalf("launch status = %d body=%s", launchResp.Code, launchResp.Body.String())
	}
	var launched LaunchAgentOutput
	if err := json.NewDecoder(launchResp.Body).Decode(&launched); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(cfg.RunsDir, launched.RunID, "output")
	if err := os.WriteFile(filepath.Join(outputDir, "report.md"), []byte("token broker-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(outputDir, "escape.md")); err != nil {
		t.Fatal(err)
	}

	req := restRequest(http.MethodGet, "/v1/runs/"+launched.RunID+"/artifacts", "operator-secret", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("artifacts status = %d body=%s", resp.Code, resp.Body.String())
	}
	var collection CollectionOutput
	if err := json.NewDecoder(resp.Body).Decode(&collection); err != nil {
		t.Fatal(err)
	}
	if len(collection.Files) != 1 || collection.Files[0].Path != "report.md" {
		t.Fatalf("collection = %+v", collection)
	}
	if strings.Contains(collection.Files[0].Inline, "broker-secret") {
		t.Fatalf("artifact inline leaked broker secret: %q", collection.Files[0].Inline)
	}
}

func TestRESTRunOperationsAreScopedToAllowedProfiles(t *testing.T) {
	cfg := restTestConfig(t)
	hidden := testLaunchProfile()
	cfg.LaunchProfiles["hidden"] = hidden
	cfg.OperatorPrincipals["hidden-launcher"] = OperatorPrincipal{
		Token:           "hidden-secret",
		AllowedProfiles: []string{"hidden"},
		AllowedActions:  []string{"launch"},
	}
	service := newRESTTestService(t, cfg, newFakeRuntime(), testAudit(t))
	handler := NewRESTHandler(service)

	launchReq := restLaunchRequest("/v1/launch-profiles/hidden/launch", "hidden-secret", "hidden-run", nil)
	launchResp := httptest.NewRecorder()
	handler.ServeHTTP(launchResp, launchReq)
	if launchResp.Code != http.StatusOK {
		t.Fatalf("hidden launch status=%d body=%s", launchResp.Code, launchResp.Body.String())
	}
	var launched LaunchAgentOutput
	if err := json.NewDecoder(launchResp.Body).Decode(&launched); err != nil {
		t.Fatal(err)
	}

	listReq := restRequest(http.MethodGet, "/v1/runs", "operator-secret", nil)
	listResp := httptest.NewRecorder()
	handler.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK || strings.Contains(listResp.Body.String(), launched.RunID) {
		t.Fatalf("scoped list status=%d body=%s", listResp.Code, listResp.Body.String())
	}

	for _, tt := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/runs/" + launched.RunID},
		{http.MethodGet, "/v1/runs/" + launched.RunID + "/logs"},
		{http.MethodGet, "/v1/runs/" + launched.RunID + "/artifacts"},
		{http.MethodGet, "/v1/runs/" + launched.RunID + "/lessons"},
		{http.MethodPost, "/v1/runs/" + launched.RunID + "/stop"},
		{http.MethodPost, "/v1/runs/" + launched.RunID + "/cleanup"},
	} {
		req := restRequest(tt.method, tt.path, "operator-secret", nil)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusNotFound {
			t.Errorf("%s %s status=%d body=%s", tt.method, tt.path, resp.Code, resp.Body.String())
		}
	}
}

func restTestConfig(t *testing.T) Config {
	t.Helper()
	cfg := baseTestConfig(t)
	cfg.LaunchIntentStore = filepath.Join(filepath.Dir(cfg.RunsDir), "state", "launch-intents.sqlite")
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": testLaunchProfile()}
	cfg.OperatorPrincipals = map[string]OperatorPrincipal{
		"timer": {
			Token:           "timer-secret",
			AllowedProfiles: []string{"nightly"},
			AllowedActions:  []string{"launch", "dry_run"},
		},
		"operator": {
			Token:           "operator-secret",
			AllowedProfiles: []string{"nightly"},
			AllowedActions:  []string{"launch", "dry_run", "status", "logs", "artifacts", "stop", "cleanup"},
			RunScope:        "profile",
		},
	}
	return cfg
}

func restRequest(method, target, token string, body []byte) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func restLaunchRequest(target, token, key string, body []byte) *http.Request {
	req := restRequest(http.MethodPost, target, token, body)
	req.Header.Set("Idempotency-Key", key)
	return req
}

func newRESTTestService(t *testing.T, cfg Config, runtime RuntimeBackend, audit *AuditLogger) *Service {
	t.Helper()
	cfg.ApplyDefaults()
	store, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close launch intent store: %v", err)
		}
	})
	return NewServiceWithLaunchIntents(cfg, runtime, audit, store)
}
