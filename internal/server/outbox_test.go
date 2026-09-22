package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gh-agent-broker/internal/correlation"
)

const testOutboxToken = "outbox-consumer-secret"

func newTestOutboxAPI(t *testing.T) (*outboxAPI, *correlation.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "correlation.sqlite")
	store, err := correlation.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open correlation store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("close store: %v", cerr)
		}
	})
	if _, err := store.Record(context.Background(), correlation.Identity{
		AgentType: "coder", Mode: "launch", RunID: "run-1", WorkItemID: "wi-1", OperationID: "op-1",
	}, "grubbyhacker/gh-agent-broker", 190); err != nil {
		t.Fatalf("record correlation: %v", err)
	}
	return newOutboxAPI(store, testOutboxToken, time.Minute, 100), store
}

func outboxReq(t *testing.T, api *outboxAPI, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	r := httptest.NewRequest(method, path, &buf)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, r)
	return rec
}

func TestOutboxRequiresAuth(t *testing.T) {
	api, _ := newTestOutboxAPI(t)

	if rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/claim", "", outboxClaimRequest{ClaimToken: "c1"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", rec.Code)
	}
	if rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/claim", "wrong", outboxClaimRequest{ClaimToken: "c1"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rec.Code)
	}
}

func TestOutboxUnmountedWithoutToken(t *testing.T) {
	api, _ := newTestOutboxAPI(t)
	api.token = ""
	// With no configured token the whole surface is 404, even with a bearer.
	if rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/claim", "anything", outboxClaimRequest{ClaimToken: "c1"}); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when unmounted", rec.Code)
	}
}

func TestOutboxRejectsNonPost(t *testing.T) {
	api, _ := newTestOutboxAPI(t)
	if rec := outboxReq(t, api, http.MethodGet, "/v1/correlation/outbox/claim", testOutboxToken, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rec.Code)
	}
}

func TestOutboxUnknownPath(t *testing.T) {
	api, _ := newTestOutboxAPI(t)
	if rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/frobnicate", testOutboxToken, outboxClaimRequest{ClaimToken: "c1"}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", rec.Code)
	}
}

func TestOutboxClaimAckDrains(t *testing.T) {
	api, store := newTestOutboxAPI(t)

	rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/claim", testOutboxToken, outboxClaimRequest{ClaimToken: "consumer-1", Limit: 10})
	if rec.Code != http.StatusOK {
		t.Fatalf("claim status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var claim outboxClaimResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &claim); err != nil {
		t.Fatalf("decode claim: %v", err)
	}
	if len(claim.Events) != 1 {
		t.Fatalf("claimed %d events, want 1", len(claim.Events))
	}
	ev := claim.Events[0]
	if ev.Version != correlation.OutboxEventVersion || ev.Status != "claimed" || ev.ClaimToken != "consumer-1" {
		t.Fatalf("event dto = %+v", ev)
	}
	// The versioned payload is carried verbatim and decodes to the recorded run.
	var payload map[string]any
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	prNumber, ok := payload["pr_number"].(float64)
	if !ok || prNumber != 190 || payload["run_id"] != "run-1" {
		t.Fatalf("payload = %+v", payload)
	}

	ack := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/ack", testOutboxToken, outboxAckRequest{EventID: ev.ID, ClaimToken: "consumer-1"})
	if ack.Code != http.StatusNoContent {
		t.Fatalf("ack status = %d, want 204 (body %s)", ack.Code, ack.Body.String())
	}
	pending, err := store.PendingCount(context.Background())
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if pending != 0 {
		t.Fatalf("after ack pending = %d, want 0", pending)
	}
}

func TestOutboxAckWrongTokenConflicts(t *testing.T) {
	api, _ := newTestOutboxAPI(t)
	rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/claim", testOutboxToken, outboxClaimRequest{ClaimToken: "consumer-1"})
	var claim outboxClaimResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &claim); err != nil {
		t.Fatalf("decode claim: %v", err)
	}
	ack := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/ack", testOutboxToken, outboxAckRequest{EventID: claim.Events[0].ID, ClaimToken: "impostor"})
	if ack.Code != http.StatusConflict {
		t.Fatalf("ack wrong token status = %d, want 409", ack.Code)
	}
	var body outboxError
	if err := json.Unmarshal(ack.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if body.Code != "claim_mismatch" {
		t.Fatalf("error code = %q, want claim_mismatch", body.Code)
	}
}

func TestOutboxReclaimReleasesForImmediateReclaim(t *testing.T) {
	api, _ := newTestOutboxAPI(t)
	rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/claim", testOutboxToken, outboxClaimRequest{ClaimToken: "consumer-1"})
	var claim outboxClaimResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &claim); err != nil {
		t.Fatalf("decode claim: %v", err)
	}
	eventID := claim.Events[0].ID

	reclaim := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/reclaim", testOutboxToken, outboxReclaimRequest{EventID: eventID, ClaimToken: "consumer-1"})
	if reclaim.Code != http.StatusNoContent {
		t.Fatalf("reclaim status = %d, want 204 (body %s)", reclaim.Code, reclaim.Body.String())
	}
	// Immediately claimable by another consumer with no TTL wait.
	rec2 := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/claim", testOutboxToken, outboxClaimRequest{ClaimToken: "consumer-2"})
	var claim2 outboxClaimResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &claim2); err != nil {
		t.Fatalf("decode second claim: %v", err)
	}
	if len(claim2.Events) != 1 || claim2.Events[0].ID != eventID {
		t.Fatalf("reclaimed event not re-claimable: %+v", claim2.Events)
	}
}

func TestOutboxRejectsBadRequests(t *testing.T) {
	api, _ := newTestOutboxAPI(t)
	// Empty claim token.
	if rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/claim", testOutboxToken, outboxClaimRequest{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty claim token status = %d, want 400", rec.Code)
	}
	// Missing event id on ack.
	if rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/ack", testOutboxToken, outboxAckRequest{ClaimToken: "c1"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing event id status = %d, want 400", rec.Code)
	}
	// Oversized body.
	big := strings.Repeat("x", maxOutboxRequestBytes+16)
	r := httptest.NewRequest(http.MethodPost, "/v1/correlation/outbox/claim", strings.NewReader(`{"claim_token":"`+big+`"}`))
	r.Header.Set("Authorization", "Bearer "+testOutboxToken)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body status = %d, want 400", rec.Code)
	}
}

// TestOutboxNeverEchoesToken guarantees the deployment-owned consumer token is
// not reflected into any response body, on success or on error.
func TestOutboxNeverEchoesToken(t *testing.T) {
	api, _ := newTestOutboxAPI(t)
	for _, path := range []string{"claim", "ack", "reclaim", "unknown"} {
		rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/"+path, testOutboxToken, map[string]any{"claim_token": "c1", "event_id": 1})
		if strings.Contains(rec.Body.String(), testOutboxToken) {
			t.Fatalf("path %q leaked the consumer token in the response body", path)
		}
	}
	// Also the unauthorized path.
	rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/claim", "wrong", outboxClaimRequest{ClaimToken: "c1"})
	if strings.Contains(rec.Body.String(), testOutboxToken) {
		t.Fatalf("unauthorized response leaked the consumer token")
	}
}

func TestOutboxClaimBatchClampedToMax(t *testing.T) {
	api, _ := newTestOutboxAPI(t)
	api.maxBatch = 1
	// Ask for more than the cap; the store call must be clamped (only 1 event
	// exists anyway, but this asserts the clamp does not error).
	rec := outboxReq(t, api, http.MethodPost, "/v1/correlation/outbox/claim", testOutboxToken, outboxClaimRequest{ClaimToken: "c1", Limit: 1000})
	if rec.Code != http.StatusOK {
		t.Fatalf("clamped claim status = %d, want 200", rec.Code)
	}
}
