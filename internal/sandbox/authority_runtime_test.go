package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
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
		body := `{"version":"agentd/control/v1","status":"ready","reasons":[],"workerId":"other-worker","storageLineageId":"11111111111111111111111111111111","fenceEpoch":2,"components":{"journal":true,"runtime":true,"launcher":true,"isolation":true}}`
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
