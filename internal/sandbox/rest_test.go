package sandbox

import (
	"bytes"
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
	service := NewService(cfg, runtime, testAudit(t))
	handler := NewRESTHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/v1/launch-profiles/nightly/launch", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want 401", resp.Code)
	}

	req = restRequest(http.MethodPost, "/v1/launch-profiles/nightly/launch", "timer-secret", nil)
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

func TestRESTDryRunAndOverridePolicy(t *testing.T) {
	cfg := restTestConfig(t)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, testAudit(t))
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
	service := NewService(cfg, runtime, auditLog)
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

	req = restRequest(http.MethodPost, "/v1/launch-profiles/nightly/launch", "timer-secret", body)
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
	service := NewService(cfg, runtime, testAudit(t))
	handler := NewRESTHandler(service)

	body := []byte(`{"parameters":{"upload_ids":["valid","too_many"]}}`)
	req := restRequest(http.MethodPost, "/v1/launch-profiles/nightly/launch", "timer-secret", body)
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
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	handler := NewRESTHandler(service)

	launchReq := restRequest(http.MethodPost, "/v1/launch-profiles/nightly/launch", "operator-secret", nil)
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

func restTestConfig(t *testing.T) Config {
	t.Helper()
	cfg := baseTestConfig(t)
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
