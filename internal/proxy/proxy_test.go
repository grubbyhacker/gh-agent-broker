package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func modelRequest(svc *Service, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/model/call", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer proxy-token")
	resp := httptest.NewRecorder()
	svc.ServeHTTP(resp, req)
	return resp
}

func writeProxyTestJSON(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}
