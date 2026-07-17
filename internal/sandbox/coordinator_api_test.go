package sandbox

import (
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
