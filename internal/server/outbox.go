package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"gh-agent-broker/internal/correlation"
)

// maxOutboxRequestBytes bounds an outbox consumer request body. The bodies are
// tiny (a claim token plus small integers / an event id); the cap is a hard
// backstop against an unexpectedly large request.
const maxOutboxRequestBytes = 8 * 1024

// outboxPathPrefix is the private route prefix Signal Plane drains through. It
// lives on the broker's existing authenticated listener; no new listener, host
// port, Cloudflare route, or firewall rule is introduced.
const outboxPathPrefix = "/v1/correlation/outbox/"

// outboxAPI is the PRIVATE broker surface for the run-to-PR correlation outbox:
// Signal Plane claims pending events, acknowledges delivered ones, and reclaims
// (negatively acknowledges) ones it cannot deliver yet. It is mounted only when
// correlation recording AND an outbox consumer token are configured, and every
// request must carry the deployment-owned consumer bearer token.
//
// The token authenticates the CONSUMER (Signal Plane) to the broker. It is the
// deployment-owned outbox consumer secret, held only by the broker and the
// consumer; it is never a run's capability handle and never enters a launched
// run's environment, metadata, log, audit, or any response body. The outbox
// payloads are broker-derived and bounded; no caller-supplied field is trusted.
type outboxAPI struct {
	store    *correlation.Store
	token    string
	claimTTL time.Duration
	maxBatch int
}

func newOutboxAPI(store *correlation.Store, token string, claimTTL time.Duration, maxBatch int) *outboxAPI {
	if maxBatch <= 0 {
		maxBatch = 1
	}
	return &outboxAPI{store: store, token: token, claimTTL: claimTTL, maxBatch: maxBatch}
}

// handleOutbox dispatches to the private outbox consumer API. The handler is
// resolved under the server mutex so a concurrent reload cannot race the field,
// consistent with the rest of the server. When correlation recording or the
// outbox consumer token is not configured the API is unmounted and the path is
// indistinguishable from any other unknown route (404), so the private surface
// does not advertise its own absence.
func (s *Server) handleOutbox(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	api := s.outbox
	s.mu.RUnlock()
	if api == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	api.ServeHTTP(w, r)
}

type outboxClaimRequest struct {
	// ClaimToken identifies the consumer's claim so it can later ack/reclaim
	// exactly what it took. Required and non-empty.
	ClaimToken string `json:"claim_token"`
	// Limit caps how many events to claim in this call. Clamped to the
	// deployment-owned max_claim_batch; a non-positive limit means 1.
	Limit int `json:"limit"`
}

// outboxEventDTO is the bounded, broker-derived projection of one outbox event.
// It carries the versioned payload verbatim (the envelope Signal Plane already
// understands) plus the claim bookkeeping the consumer needs to ack/reclaim. It
// never exposes any broker secret.
type outboxEventDTO struct {
	ID         int64           `json:"id"`
	Version    string          `json:"version"`
	Status     string          `json:"status"`
	Attempts   int64           `json:"attempts"`
	Payload    json.RawMessage `json:"payload"`
	ClaimToken string          `json:"claim_token"`
	ClaimedAt  string          `json:"claimed_at,omitempty"`
	CreatedAt  string          `json:"created_at"`
	UpdatedAt  string          `json:"updated_at"`
}

type outboxClaimResponse struct {
	Events []outboxEventDTO `json:"events"`
}

type outboxAckRequest struct {
	EventID    int64  `json:"event_id"`
	ClaimToken string `json:"claim_token"`
}

type outboxReclaimRequest struct {
	EventID    int64  `json:"event_id"`
	ClaimToken string `json:"claim_token"`
}

func (a *outboxAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.store == nil || a.token == "" {
		http.NotFound(w, r)
		return
	}
	if !a.authenticated(r) {
		writeOutboxError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeOutboxError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, outboxPathPrefix), "/")
	switch path {
	case "claim":
		a.handleClaim(w, r)
	case "ack":
		a.handleAck(w, r)
	case "reclaim":
		a.handleReclaim(w, r)
	default:
		writeOutboxError(w, http.StatusNotFound, "not_found")
	}
}

func (a *outboxAPI) authenticated(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	presented := strings.TrimPrefix(auth, prefix)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(a.token)) == 1
}

func (a *outboxAPI) handleClaim(w http.ResponseWriter, r *http.Request) {
	var req outboxClaimRequest
	if !decodeOutboxRequest(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.ClaimToken) == "" {
		writeOutboxError(w, http.StatusBadRequest, "claim_token_required")
		return
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 1
	}
	if limit > a.maxBatch {
		limit = a.maxBatch
	}
	events, err := a.store.ClaimPending(r.Context(), req.ClaimToken, limit, a.claimTTL)
	if err != nil {
		writeOutboxStoreError(w, err)
		return
	}
	dtos := make([]outboxEventDTO, 0, len(events))
	for _, event := range events {
		dtos = append(dtos, toOutboxEventDTO(event))
	}
	writeOutboxJSON(w, http.StatusOK, outboxClaimResponse{Events: dtos})
}

func (a *outboxAPI) handleAck(w http.ResponseWriter, r *http.Request) {
	var req outboxAckRequest
	if !decodeOutboxRequest(w, r, &req) {
		return
	}
	if req.EventID <= 0 || strings.TrimSpace(req.ClaimToken) == "" {
		writeOutboxError(w, http.StatusBadRequest, "event_id_and_claim_token_required")
		return
	}
	if err := a.store.Ack(r.Context(), req.EventID, req.ClaimToken); err != nil {
		writeOutboxStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *outboxAPI) handleReclaim(w http.ResponseWriter, r *http.Request) {
	var req outboxReclaimRequest
	if !decodeOutboxRequest(w, r, &req) {
		return
	}
	if req.EventID <= 0 || strings.TrimSpace(req.ClaimToken) == "" {
		writeOutboxError(w, http.StatusBadRequest, "event_id_and_claim_token_required")
		return
	}
	if err := a.store.Reclaim(r.Context(), req.EventID, req.ClaimToken); err != nil {
		writeOutboxStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func toOutboxEventDTO(event correlation.OutboxEvent) outboxEventDTO {
	dto := outboxEventDTO{
		ID:         event.ID,
		Version:    event.Version,
		Status:     event.Status,
		Attempts:   event.Attempts,
		Payload:    json.RawMessage(event.Payload),
		ClaimToken: event.ClaimToken,
		CreatedAt:  event.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:  event.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if event.ClaimedAt != nil {
		dto.ClaimedAt = event.ClaimedAt.UTC().Format(time.RFC3339Nano)
	}
	return dto
}

func decodeOutboxRequest(w http.ResponseWriter, r *http.Request, out any) bool {
	defer func() {
		if err := r.Body.Close(); err != nil {
			_ = err
		}
	}()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxOutboxRequestBytes+1))
	if err != nil || len(body) > maxOutboxRequestBytes {
		writeOutboxError(w, http.StatusBadRequest, "request body invalid or too large")
		return false
	}
	if err := json.Unmarshal(body, out); err != nil {
		writeOutboxError(w, http.StatusBadRequest, "invalid json")
		return false
	}
	return true
}

func writeOutboxStoreError(w http.ResponseWriter, err error) {
	// Never echo internal detail; map to a bounded status + code.
	switch {
	case errors.Is(err, correlation.ErrClaimMismatch):
		writeOutboxError(w, http.StatusConflict, "claim_mismatch")
	case errors.Is(err, correlation.ErrNotFound):
		writeOutboxError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, correlation.ErrPayloadBounds):
		writeOutboxError(w, http.StatusUnprocessableEntity, "payload_bounds")
	default:
		writeOutboxError(w, http.StatusBadRequest, "outbox_request_denied")
	}
}

type outboxError struct {
	Code string `json:"code"`
}

func writeOutboxError(w http.ResponseWriter, status int, code string) {
	writeOutboxJSON(w, status, outboxError{Code: code})
}

func writeOutboxJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		_ = err
	}
}
