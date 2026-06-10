package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModelCallForwardsToUpstreamAndTracksBudget(t *testing.T) {
	var sawAuth bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("upstream path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "Bearer upstream-secret" {
			sawAuth = true
		}
		writeProxyTestJSON(t, w, map[string]interface{}{
			"id":    "chat-1",
			"model": "gpt-test",
			"choices": []map[string]interface{}{{
				"message": map[string]interface{}{"content": `{"ok":true}`},
			}},
			"usage": map[string]int{"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7},
		})
	}))
	defer upstream.Close()

	svc := newTestService(t, upstream.URL+"/v1")
	body := `{"run_id":"run-1","model":"gpt-test","messages":[{"role":"user","content":"private"}]}`
	resp := modelRequest(svc, body)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", resp.Code, resp.Body.String())
	}
	if !sawAuth {
		t.Fatalf("upstream Authorization was not set")
	}
	if strings.Contains(resp.Body.String(), "upstream-secret") {
		t.Fatalf("response exposed upstream key")
	}
}

func TestModelCallDeniesDisallowedModelAndCallBudget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProxyTestJSON(t, w, map[string]interface{}{
			"choices": []map[string]interface{}{{"message": map[string]string{"content": "ok"}}},
			"usage":   map[string]int{"total_tokens": 1},
		})
	}))
	defer upstream.Close()
	svc := newTestService(t, upstream.URL+"/v1")

	resp := modelRequest(svc, `{"run_id":"run-1","model":"forbidden","messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("forbidden model status = %d", resp.Code)
	}

	resp = modelRequest(svc, `{"run_id":"run-2","model":"gpt-test","messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("first call status = %d", resp.Code)
	}
	resp = modelRequest(svc, `{"run_id":"run-2","model":"gpt-test","messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("second call status = %d, want 429", resp.Code)
	}
}

func TestCodexModelsReturnsAllowedAliases(t *testing.T) {
	svc, _ := newCodexTestService(t, "http://127.0.0.1:1/v1")
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer codex-token")
	resp := httptest.NewRecorder()
	svc.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	for _, want := range []string{"ykm-codex-haiku", "ykm-codex-sonnet"} {
		if !strings.Contains(body, want) {
			t.Fatalf("models response missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "anthropic/claude") {
		t.Fatalf("models response exposed upstream model ids: %s", body)
	}
}

func TestCodexResponsesForwardsAliasAndTracksBudget(t *testing.T) {
	var sawAuth bool
	var upstreamModel string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("upstream path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "Bearer codex-upstream-secret" {
			sawAuth = true
		}
		if strings.Contains(r.Header.Get("Authorization"), "codex-token") {
			t.Fatalf("forwarded executor token upstream")
		}
		var body struct {
			Model string `json:"model"`
			Input string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		upstreamModel = body.Model
		if body.Input != "private prompt body" {
			t.Fatalf("input = %q", body.Input)
		}
		writeProxyTestJSON(t, w, map[string]interface{}{
			"id":     "resp-1",
			"object": "response",
			"model":  body.Model,
			"output": []map[string]interface{}{{"type": "message"}},
			"usage":  map[string]int{"input_tokens": 3, "output_tokens": 4, "total_tokens": 7},
		})
	}))
	defer upstream.Close()
	svc, auditPath := newCodexTestService(t, upstream.URL+"/v1")

	resp := codexResponseRequest(svc, `{"model":"ykm-codex-sonnet","input":"private prompt body"}`, "run-codex-1")
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", resp.Code, resp.Body.String())
	}
	if !sawAuth {
		t.Fatalf("upstream Authorization was not set")
	}
	if upstreamModel != "anthropic/claude-sonnet-4.5" {
		t.Fatalf("upstream model = %q", upstreamModel)
	}
	state := readTestBudget(t, svc)
	if got := state.Runs["run-codex-1"]; got.Calls != 1 || got.Tokens != 7 {
		t.Fatalf("budget = %+v, want 1 call and 7 tokens", got)
	}
	audit := readTestFile(t, auditPath)
	for _, want := range []string{`"endpoint":"/v1/responses"`, `"run_id":"run-codex-1"`, `"model":"ykm-codex-sonnet"`, `"tokens":7`} {
		if !strings.Contains(audit, want) {
			t.Fatalf("audit missing %s: %s", want, audit)
		}
	}
	for _, secret := range []string{"private prompt body", "codex-token", "codex-upstream-secret"} {
		if strings.Contains(audit, secret) {
			t.Fatalf("audit leaked %q: %s", secret, audit)
		}
	}
}

func TestCodexResponsesDenials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProxyTestJSON(t, w, map[string]interface{}{
			"id":    "resp-1",
			"usage": map[string]int{"total_tokens": 1},
		})
	}))
	defer upstream.Close()
	svc, _ := newCodexTestService(t, upstream.URL+"/v1")

	resp := codexResponseRequest(svc, `{"model":"ykm-codex-haiku","input":"x"}`, "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("missing run id status = %d", resp.Code)
	}
	resp = codexResponseRequest(svc, `{"model":"forbidden","input":"x"}`, "run-deny")
	if resp.Code != http.StatusForbidden {
		t.Fatalf("forbidden model status = %d", resp.Code)
	}
	resp = codexResponseRequest(svc, `{"model":"ykm-codex-haiku","input":"x"}`, "run-budget")
	if resp.Code != http.StatusOK {
		t.Fatalf("first budget call status = %d", resp.Code)
	}
	resp = codexResponseRequest(svc, `{"model":"ykm-codex-haiku","input":"x"}`, "run-budget")
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("second budget call status = %d", resp.Code)
	}
}

func TestCodexResponsesStreamsSSE(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := io.WriteString(w, "event: response.output_text.delta\n"); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, "data: {\"delta\":\"hello\"}\n\n"); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, "data: {\"usage\":{\"total_tokens\":9}}\n\n"); err != nil {
			t.Fatal(err)
		}
	}))
	defer upstream.Close()
	svc, _ := newCodexTestService(t, upstream.URL+"/v1")

	resp := codexResponseRequest(svc, `{"model":"ykm-codex-haiku","stream":true,"input":"x"}`, "run-stream")
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", resp.Code, resp.Body.String())
	}
	if got := resp.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("content-type = %q", got)
	}
	if !strings.Contains(resp.Body.String(), `"delta":"hello"`) {
		t.Fatalf("stream body not passed through: %s", resp.Body.String())
	}
	state := readTestBudget(t, svc)
	if got := state.Runs["run-stream"]; got.Calls != 1 || got.Tokens != 9 {
		t.Fatalf("budget = %+v, want 1 call and 9 tokens", got)
	}
}

func TestCodexResponsesWithoutUsageCountsOneCall(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProxyTestJSON(t, w, map[string]interface{}{
			"id":     "resp-no-usage",
			"object": "response",
		})
	}))
	defer upstream.Close()
	svc, _ := newCodexTestService(t, upstream.URL+"/v1")
	svc.cfg.MaxCallsPerRun = 5

	resp := codexResponseRequest(svc, `{"model":"ykm-codex-haiku","input":"x"}`, "run-no-usage")
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", resp.Code, resp.Body.String())
	}
	state := readTestBudget(t, svc)
	if got := state.Runs["run-no-usage"]; got.Calls != 1 || got.Tokens != 0 {
		t.Fatalf("budget = %+v, want 1 call and 0 tokens", got)
	}
}

func TestCodexResponsesStreamWithoutUsageCountsOneCall(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := io.WriteString(w, "data: {\"delta\":\"hello\"}\n\n"); err != nil {
			t.Fatal(err)
		}
	}))
	defer upstream.Close()
	svc, _ := newCodexTestService(t, upstream.URL+"/v1")
	svc.cfg.MaxCallsPerRun = 5

	resp := codexResponseRequest(svc, `{"model":"ykm-codex-haiku","stream":true,"input":"x"}`, "run-stream-no-usage")
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", resp.Code, resp.Body.String())
	}
	state := readTestBudget(t, svc)
	if got := state.Runs["run-stream-no-usage"]; got.Calls != 1 || got.Tokens != 0 {
		t.Fatalf("budget = %+v, want 1 call and 0 tokens", got)
	}
}

func newTestService(t *testing.T, upstream string) *Service {
	t.Helper()
	svc, err := NewService(Config{
		AuthToken:        "proxy-token",
		UpstreamURL:      upstream,
		UpstreamKey:      "upstream-secret",
		AllowedModels:    []string{"gpt-test"},
		StatePath:        filepath.Join(t.TempDir(), "state.json"),
		MaxCallsPerRun:   1,
		MaxTokensPerRun:  100,
		MaxRequestBytes:  4096,
		MaxResponseBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func newCodexTestService(t *testing.T, upstream string) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	svc, err := NewService(Config{
		AuthToken:          "proxy-token",
		CodexAuthToken:     "codex-token",
		UpstreamURL:        upstream,
		UpstreamKey:        "upstream-secret",
		CodexUpstreamKey:   "codex-upstream-secret",
		AllowedModels:      []string{"gpt-test"},
		CodexAllowedModels: []CodexModelConfig{{Name: "ykm-codex-haiku", UpstreamModel: "anthropic/claude-haiku-4.5"}, {Name: "ykm-codex-sonnet", UpstreamModel: "anthropic/claude-sonnet-4.5"}},
		StatePath:          filepath.Join(dir, "state.json"),
		AuditPath:          auditPath,
		MaxCallsPerRun:     1,
		MaxTokensPerRun:    100,
		MaxRequestBytes:    4096,
		MaxResponseBytes:   4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := svc.audit.Close(); err != nil {
			t.Fatal(err)
		}
	})
	return svc, auditPath
}

func modelRequest(svc *Service, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/model/call", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer proxy-token")
	resp := httptest.NewRecorder()
	svc.ServeHTTP(resp, req)
	return resp
}

func codexResponseRequest(svc *Service, body, runID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer codex-token")
	if runID != "" {
		req.Header.Set("X-GH-Agent-Run-ID", runID)
	}
	resp := httptest.NewRecorder()
	svc.ServeHTTP(resp, req)
	return resp
}

func readTestBudget(t *testing.T, svc *Service) budgetState {
	t.Helper()
	state, err := svc.readBudget()
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	// #nosec G304 -- tests pass only t.TempDir-created audit file paths.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeProxyTestJSON(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}
