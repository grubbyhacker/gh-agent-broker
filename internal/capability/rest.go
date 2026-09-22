package capability

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxRequestBytes bounds a capability REST request body. The bodies are tiny
// (a handle plus small integers); the cap is a hard backstop.
const maxRequestBytes = 8 * 1024

// RESTHandler is the PRIVATE sandbox-broker surface for capability
// verify/reserve/revoke. It is mounted only when a capability store is
// configured, and every request must carry the configured bearer token. The
// handle travels in the request body and is never written to a response, log,
// or error.
type RESTHandler struct {
	store *Store
	token string
	now   func() time.Time
}

// NewRESTHandler builds the private handler. token must be non-empty — the
// endpoints are refused entirely without a configured auth token.
func NewRESTHandler(store *Store, token string) *RESTHandler {
	return &RESTHandler{store: store, token: token, now: time.Now}
}

type verifyRequest struct {
	Handle string `json:"handle"`
}

type verifyResponse struct {
	AgentType      string   `json:"agent_type"`
	Mode           string   `json:"mode"`
	RunID          string   `json:"run_id"`
	WorkItemID     string   `json:"work_item_id"`
	AllowedModels  []string `json:"allowed_models"`
	CallBudget     int64    `json:"call_budget"`
	TokenBudget    int64    `json:"token_budget"`
	Expiry         string   `json:"expiry"`
	ReservedCalls  int64    `json:"reserved_calls"`
	ReservedTokens int64    `json:"reserved_tokens"`
}

type reserveRequest struct {
	Handle string `json:"handle"`
	Model  string `json:"model,omitempty"`
	Calls  int64  `json:"calls"`
	Tokens int64  `json:"tokens"`
}

type reserveResponse struct {
	ReservedCalls  int64 `json:"reserved_calls"`
	ReservedTokens int64 `json:"reserved_tokens"`
}

type revokeRequest struct {
	Handle string `json:"handle"`
}

func (h *RESTHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.store == nil || h.token == "" {
		http.NotFound(w, r)
		return
	}
	if !h.authenticated(r) {
		writeCapError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeCapError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/capabilities/"), "/")
	switch path {
	case "verify":
		h.handleVerify(w, r)
	case "reserve":
		h.handleReserve(w, r)
	case "revoke":
		h.handleRevoke(w, r)
	default:
		writeCapError(w, http.StatusNotFound, "not_found")
	}
}

func (h *RESTHandler) authenticated(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	presented := strings.TrimPrefix(auth, prefix)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(h.token)) == 1
}

func (h *RESTHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if !decodeCapRequest(w, r, &req) {
		return
	}
	claims, res, err := h.store.Verify(r.Context(), req.Handle)
	if err != nil {
		writeCapStoreError(w, err)
		return
	}
	writeCapJSON(w, http.StatusOK, verifyResponse{
		AgentType: claims.AgentType(), Mode: string(claims.Mode()), RunID: claims.RunID(),
		WorkItemID: claims.WorkItemID(), AllowedModels: claims.AllowedModels(),
		CallBudget: claims.CallBudget(), TokenBudget: claims.TokenBudget(),
		Expiry:        claims.Expiry().Format(time.RFC3339Nano),
		ReservedCalls: res.Calls, ReservedTokens: res.Tokens,
	})
}

func (h *RESTHandler) handleReserve(w http.ResponseWriter, r *http.Request) {
	var req reserveRequest
	if !decodeCapRequest(w, r, &req) {
		return
	}
	if req.Calls < 0 || req.Tokens < 0 {
		writeCapError(w, http.StatusBadRequest, "negative reservation")
		return
	}
	// Verify first to derive the trusted identity for the authorize check; the
	// store re-reads reserved totals inside the reservation transaction.
	claims, _, err := h.store.Verify(r.Context(), req.Handle)
	if err != nil {
		writeCapStoreError(w, err)
		return
	}
	res, err := h.store.Reserve(r.Context(), req.Handle, Request{
		AgentType: claims.AgentType(), Mode: claims.Mode(), RunID: claims.RunID(),
		WorkItemID: claims.WorkItemID(), Model: req.Model, Calls: req.Calls, Tokens: req.Tokens,
	})
	if err != nil {
		writeCapStoreError(w, err)
		return
	}
	writeCapJSON(w, http.StatusOK, reserveResponse{ReservedCalls: res.Calls, ReservedTokens: res.Tokens})
}

func (h *RESTHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if !decodeCapRequest(w, r, &req) {
		return
	}
	if err := h.store.Revoke(r.Context(), req.Handle); err != nil {
		writeCapStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeCapRequest(w http.ResponseWriter, r *http.Request, out any) bool {
	defer func() {
		if err := r.Body.Close(); err != nil {
			_ = err
		}
	}()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil || len(body) > maxRequestBytes {
		writeCapError(w, http.StatusBadRequest, "request body invalid or too large")
		return false
	}
	if err := json.Unmarshal(body, out); err != nil {
		writeCapError(w, http.StatusBadRequest, "invalid json")
		return false
	}
	return true
}

func writeCapStoreError(w http.ResponseWriter, err error) {
	// Never echo the handle or internal detail; map to a bounded status+code.
	switch {
	case errors.Is(err, ErrHandleMalformed):
		writeCapError(w, http.StatusBadRequest, "handle_malformed")
	case errors.Is(err, ErrHandleNotFound):
		writeCapError(w, http.StatusNotFound, "handle_not_found")
	case errors.Is(err, ErrRevoked):
		writeCapError(w, http.StatusConflict, "revoked")
	case errors.Is(err, ErrExpired):
		writeCapError(w, http.StatusConflict, "expired")
	case errors.Is(err, ErrModelDenied):
		writeCapError(w, http.StatusForbidden, "model_denied")
	case errors.Is(err, ErrCallBudget):
		writeCapError(w, http.StatusConflict, "call_budget_exhausted")
	case errors.Is(err, ErrTokenBudget):
		writeCapError(w, http.StatusConflict, "token_budget_exhausted")
	case errors.Is(err, ErrInvalidClaims):
		writeCapError(w, http.StatusUnprocessableEntity, "invalid_claims")
	default:
		writeCapError(w, http.StatusBadRequest, "reservation_denied")
	}
}

type capError struct {
	Code string `json:"code"`
}

func writeCapError(w http.ResponseWriter, status int, code string) {
	writeCapJSON(w, status, capError{Code: code})
}

func writeCapJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		_ = err
	}
}
