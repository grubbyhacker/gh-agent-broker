package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestAuthenticatedAgentdReadinessRejectsIdentityMismatch(t *testing.T) {
	worker := AuthorityWorker{
		WorkerID:               "worker-one",
		WorkerStorageLineageID: "11111111111111111111111111111111",
		WorkerFenceEpoch:       2,
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("Authorization"); got != "Bearer coordinator-token" {
			t.Fatalf("authorization=%q", got)
		}
		body := `{"version":"agentd/control/v1","status":"ready","reasons":[],"workerId":"other-worker","storageLineageId":"11111111111111111111111111111111","fenceEpoch":2,"components":{"journal":true,"runtime":true,"launcher":true,"isolation":true,"brokerFenceValidatorConfigured":true}}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://agentd.invalid/readyz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer coordinator-token")
	ready, evidence, err := probeAgentdReadiness(client, req, "agentd/control/v1", worker)
	if err != nil || ready || evidence != "agentd_readiness_identity_mismatch" {
		t.Fatalf("ready=%t evidence=%q err=%v", ready, evidence, err)
	}
}

func TestAuthenticatedAgentdReadinessRequiresConfiguredBrokerFenceValidator(t *testing.T) {
	worker := AuthorityWorker{WorkerID: "worker-one", WorkerStorageLineageID: "11111111111111111111111111111111", WorkerFenceEpoch: 2}
	base := `{"version":"agentd/control/v1","status":"ready","reasons":[],"workerId":"worker-one","storageLineageId":"11111111111111111111111111111111","fenceEpoch":2,"components":%s}`
	for name, test := range map[string]struct {
		components string
		ready      bool
		evidence   string
	}{
		"configured": {`{"journal":true,"runtime":true,"launcher":true,"isolation":true,"brokerFenceValidatorConfigured":true}`, true, "agentd_authenticated_readiness_ok"},
		"false":      {`{"journal":true,"runtime":true,"launcher":true,"isolation":true,"brokerFenceValidatorConfigured":false}`, false, "agentd_readiness_subsystem_unavailable"},
		"missing":    {`{"journal":true,"runtime":true,"launcher":true,"isolation":true}`, false, "agentd_readiness_malformed"},
		"retired":    {`{"journal":true,"runtime":true,"launcher":true,"isolation":true,"brokerFenceValidator":true}`, false, "agentd_readiness_malformed"},
	} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(base, test.components))), Header: make(http.Header)}, nil
			})}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://agentd.invalid/readyz", nil)
			if err != nil {
				t.Fatal(err)
			}
			ready, evidence, err := probeAgentdReadiness(client, req, "agentd/control/v1", worker)
			if err != nil || ready != test.ready || evidence != test.evidence {
				t.Fatalf("ready=%t evidence=%q err=%v", ready, evidence, err)
			}
		})
	}
}

func TestAgentdCreateSessionPayloadMatchesCurrentSchema(t *testing.T) {
	payload, err := json.Marshal(agentdCreateSessionRequest{
		Version:            "agentd/v1",
		CoordinatorBinding: "coordinator-session",
		AuthorityBinding:   "writer",
		WorkerID:           "worker-one",
		StorageLineageID:   "11111111111111111111111111111111",
		FenceEpoch:         2,
		SessionLineageID:   "22222222222222222222222222222222",
		Workspace:          agentdSessionWorkspace{WorkspaceRef: agentdControlV1WorkspaceRoot + "/22222222222222222222222222222222", UID: 20000, GID: 20000},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	wantTop := []string{"authorityBinding", "coordinatorBinding", "fenceEpoch", "sessionLineageId", "storageLineageId", "version", "workerId", "workspace"}
	gotTop := make([]string, 0, len(got))
	for key := range got {
		gotTop = append(gotTop, key)
	}
	sort.Strings(gotTop)
	if !reflect.DeepEqual(gotTop, wantTop) {
		t.Fatalf("top-level payload fields=%q, want %q", gotTop, wantTop)
	}
	workspace, ok := got["workspace"].(map[string]any)
	if !ok {
		t.Fatalf("workspace=%T", got["workspace"])
	}
	gotWorkspace := make([]string, 0, len(workspace))
	for key := range workspace {
		gotWorkspace = append(gotWorkspace, key)
	}
	sort.Strings(gotWorkspace)
	if want := []string{"gid", "uid", "workspaceRef"}; !reflect.DeepEqual(gotWorkspace, want) {
		t.Fatalf("workspace payload fields=%q, want %q", gotWorkspace, want)
	}
}

func TestAgentdRegisteredSessionOpenPayloadBindsDurableAdmission(t *testing.T) {
	const admissionDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	payload, err := json.Marshal(agentdRegisteredSessionOpenRequest{
		Version: "agentd/registered-lifecycle/v1", SessionID: "agentd-session", CoordinatorBinding: "session:work",
		SessionLineageID: "lineage", AuthorityProfile: "writer", AuthorityProfileVersion: "profile-v1", PolicyDigest: "sha256:policy",
		TaskKind: "github_green_pr_v1", TaskEvidenceDigest: "sha256:evidence", AdmissionTaskDigest: admissionDigest,
		Parameters: RegisteredTaskParameters{Repository: "grubbyhacker/repository-worker-lifecycle-test", BaseBranch: "main", BranchRef: "agent/fleiglabs-repo-agent/work"},
		Workspace:  agentdSessionWorkspace{WorkspaceRef: "/workspace", UID: 20000, GID: 20000},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if digest, ok := got["admissionTaskDigest"].(string); !ok || digest != admissionDigest {
		t.Fatalf("admissionTaskDigest=%#v, want %q", got["admissionTaskDigest"], admissionDigest)
	}
	if _, ok := got["registeredTaskDigest"]; ok {
		t.Fatalf("registeredTaskDigest must not be emitted: %s", payload)
	}
}

func TestAgentdRebindUsesCoordinatorChannelAndExactBody(t *testing.T) {
	request := agentdRebindRequest{
		IdempotencyKey: "broker-derived-key",
		Predecessor:    agentdWorkerBinding{WorkerID: "old", StorageLineageID: "storage", FenceEpoch: 1},
		Successor:      agentdWorkerBinding{WorkerID: "new", StorageLineageID: "storage", FenceEpoch: 2},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sessions/agentd-session/rebind" {
			t.Fatalf("request method=%s path=%s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer coordinator-secret" {
			t.Fatalf("authorization=%q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("coordinator-secret")) || bytes.Contains(body, []byte("endpoint")) {
			t.Fatalf("credential or endpoint leaked into body: %s", body)
		}
		var got agentdRebindRequest
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&got); err != nil || got != request {
			t.Fatalf("body=%s decoded=%+v err=%v", body, got, err)
		}
		status := agentdSessionStatus{
			Version: agentdSessionProtocolVersion, SessionID: "agentd-session", CoordinatorBinding: "binding", AuthorityBinding: "writer",
			WorkerID: "new", StorageLineageID: "storage", FenceEpoch: 2, SessionLineageID: "session-lineage",
			Workspace: agentdSessionWorkspace{WorkspaceRef: "/workspace", UID: 20000, GID: 20000}, Phase: "active", TurnIDs: []string{}, NextCursor: 2,
		}
		writeJSON(w, http.StatusOK, status)
	}))
	t.Cleanup(server.Close)
	status, err := postAgentdRebind(context.Background(), server.Client(), server.URL+"/v1/sessions/agentd-session/rebind", "coordinator-secret", request)
	if err != nil || status.WorkerID != "new" || status.SessionID != "agentd-session" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestRegisteredAgentdAdoptionUsesExactRouteAndBody(t *testing.T) {
	request := agentdRegisteredAdoptRequest{Version: "agentd/registered-lifecycle/v1", IdempotencyKey: "broker-derived-key", PredecessorWorker: "old", PredecessorEpoch: 1}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/registered-sessions/agentd-session/adopt" {
			t.Fatalf("request method=%s path=%s", r.Method, r.URL.Path)
		}
		var got agentdRegisteredAdoptRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&got); err != nil || got != request {
			t.Fatalf("body decoded=%+v err=%v", got, err)
		}
		writeJSON(w, http.StatusOK, agentdSessionStatus{Version: agentdSessionProtocolVersion, SessionID: "agentd-session", CoordinatorBinding: "binding", AuthorityBinding: "writer", WorkerID: "new", StorageLineageID: "storage", FenceEpoch: 2, SessionLineageID: "session-lineage", Workspace: agentdSessionWorkspace{WorkspaceRef: "/workspace", UID: 20000, GID: 20000}, Phase: "active", TurnIDs: []string{}, NextCursor: 2})
	}))
	t.Cleanup(server.Close)
	status, err := postAgentdRegisteredAdoption(context.Background(), server.Client(), server.URL+"/v1/registered-sessions/agentd-session/adopt", "coordinator-secret", request)
	if err != nil || status.WorkerID != "new" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestAgentdRebindClassifiesRetryableAndTerminalResponses(t *testing.T) {
	request := agentdRebindRequest{IdempotencyKey: "key", Predecessor: agentdWorkerBinding{WorkerID: "old", StorageLineageID: "storage", FenceEpoch: 1}, Successor: agentdWorkerBinding{WorkerID: "new", StorageLineageID: "storage", FenceEpoch: 2}}
	for name, response := range map[string]struct {
		status    int
		body      string
		retryable bool
		code      string
	}{
		"validator unavailable": {http.StatusServiceUnavailable, `{"error":"broker_validator_unavailable"}`, true, ""},
		"storage unavailable":   {http.StatusServiceUnavailable, `{"error":"session_storage_unavailable"}`, true, ""},
		"malformed success":     {http.StatusOK, `{"workerId":"new"}`, true, ""},
		"semantic conflict":     {http.StatusConflict, `{"error":"rebind_conflict"}`, false, "rebind_conflict"},
		"fenced":                {http.StatusConflict, `{"error":"session_fenced","brokerCode":"fenced"}`, false, "session_fenced"},
		"generic bad request":   {http.StatusBadRequest, `{"error":"invalid_command"}`, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: response.status, Body: io.NopCloser(strings.NewReader(response.body)), Header: make(http.Header)}, nil
			})}
			_, err := postAgentdRebind(context.Background(), client, "http://agentd.invalid/v1/sessions/session/rebind", "secret", request)
			var typed *agentdRebindError
			if !errors.As(err, &typed) || typed.retryable != response.retryable || typed.code != response.code {
				t.Fatalf("error=%#v", err)
			}
		})
	}
}
