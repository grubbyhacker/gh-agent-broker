package sandbox

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func TestCoordinatorAgentdRequestUsesOnlyFixedOperations(t *testing.T) {
	tests := []struct {
		operation, method, path string
		request                 CoordinatorSessionRequest
	}{
		{"submit", http.MethodPost, "/v1/sessions/session-1/turns", CoordinatorSessionRequest{SessionBinding: "binding", Prompt: "prompt", IdempotencyKey: "key"}},
		{"events", http.MethodGet, "/v1/sessions/session-1/events?after=7", CoordinatorSessionRequest{SessionBinding: "binding", After: 7}},
		{"checkpoint", http.MethodPost, "/v1/sessions/session-1/checkpoint", CoordinatorSessionRequest{SessionBinding: "binding", CheckpointRef: "checkpoint-1"}},
		{"resume", http.MethodPost, "/v1/sessions/session-1/resume", CoordinatorSessionRequest{SessionBinding: "binding"}},
		{"cancel", http.MethodPost, "/v1/sessions/session-1/cancel", CoordinatorSessionRequest{SessionBinding: "binding", TurnID: "turn-1"}},
		{"status", http.MethodGet, "/v1/sessions/session-1/status", CoordinatorSessionRequest{SessionBinding: "binding"}},
	}
	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			if err := validateCoordinatorSessionRequest(test.operation, test.request); err != nil {
				t.Fatal(err)
			}
			method, path, _ := coordinatorAgentdRequest(test.operation, "session-1", test.request)
			if method != test.method || path != test.path {
				t.Fatalf("method=%s path=%s", method, path)
			}
		})
	}
}

func TestRegisteredCoordinatorAgentdRequestUsesRegisteredRoutes(t *testing.T) {
	task := registeredRequest(t, "route-work", "route-snapshot").Task
	for _, test := range []struct {
		operation, path string
		request         CoordinatorSessionRequest
	}{
		{"submit", "/v1/registered-sessions/session-1/turns", CoordinatorSessionRequest{SessionBinding: "binding", IdempotencyKey: "key"}},
		{"events", "/v1/registered-sessions/session-1/events?version=agentd%2Fregistered-lifecycle%2Fv1&after=7", CoordinatorSessionRequest{SessionBinding: "binding", After: 7}},
		{"checkpoint", "/v1/registered-sessions/session-1/checkpoint", CoordinatorSessionRequest{SessionBinding: "binding", CheckpointRef: "checkpoint-1"}},
		{"cancel", "/v1/registered-sessions/session-1/cancel", CoordinatorSessionRequest{SessionBinding: "binding", IdempotencyKey: "key"}},
		{"status", "/v1/registered-sessions/session-1/status?version=agentd%2Fregistered-lifecycle%2Fv1", CoordinatorSessionRequest{SessionBinding: "binding"}},
	} {
		t.Run(test.operation, func(t *testing.T) {
			if err := validateCoordinatorSessionRequestForBinding(test.operation, test.request, true); err != nil {
				t.Fatal(err)
			}
			method, path, body := coordinatorRegisteredAgentdRequest(test.operation, "session-1", test.request, task)
			if path != test.path {
				t.Fatalf("path=%s", path)
			}
			if test.operation == "submit" && (method != http.MethodPost || bytes.Contains(body, []byte("prompt")) || !bytes.Contains(body, []byte(task.Parameters.BranchRef))) {
				t.Fatalf("body=%s", body)
			}
			if test.operation == "checkpoint" || test.operation == "cancel" {
				var got map[string]string
				if err := json.Unmarshal(body, &got); err != nil || got["version"] != "agentd/registered-lifecycle/v1" {
					t.Fatalf("body=%s err=%v", body, err)
				}
			}
		})
	}
	if err := validateCoordinatorSessionRequestForBinding("resume", CoordinatorSessionRequest{SessionBinding: "binding"}, true); err == nil {
		t.Fatal("registered resume accepted")
	}
}

func TestCoordinatorAgentdResultsRejectCrossSessionEvidence(t *testing.T) {
	if err := validateCoordinatorAgentdResult("submit", "session-1", 0, []byte(`{"sessionId":"other","turnId":"turn-1","phase":"queued"}`)); err == nil {
		t.Fatal("cross-session turn accepted")
	}
	if err := validateCoordinatorAgentdResult("events", "session-1", 3, []byte(`[{"version":"agentd/v1","cursor":4,"kind":"attempt_completed","sessionId":"other"}]`)); err == nil {
		t.Fatal("cross-session event accepted")
	}
	if err := validateCoordinatorAgentdResult("events", "session-1", 3, []byte(`[{"version":"agentd/v1","cursor":5,"kind":"evidence","sessionId":"session-1"},{"version":"agentd/v1","cursor":4,"kind":"usage","sessionId":"session-1"}]`)); err == nil {
		t.Fatal("regressing cursor accepted")
	}
}
