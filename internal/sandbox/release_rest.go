package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"gh-agent-broker/internal/release"
)

// ReleaseRegistry is the narrow registry surface exposed through REST.
// Authentication is intentionally not part of this interface.
type ReleaseRegistry interface {
	PublishCandidate(context.Context, string, string, release.Provenance, string) (release.Release, error)
	Verify(context.Context, int64, release.Requirements, string) error
	MarkAvailable(context.Context, int64, bool, string) error
	Promote(context.Context, int64, string) error
	Rollback(context.Context, string, int64, string) error
}

type publishReleaseRequest struct {
	AgentType      string             `json:"agent_type"`
	ImageReference string             `json:"image_reference"`
	Provenance     release.Provenance `json:"provenance"`
}

type verifyReleaseRequest struct {
	Requirements release.Requirements `json:"requirements"`
}

type rollbackReleaseRequest struct {
	Generation int64 `json:"generation"`
}

func (h *restHandler) handleRelease(w http.ResponseWriter, r *http.Request, path string) {
	if h.releases == nil {
		writeRESTCodeError(w, http.StatusServiceUnavailable, "release_registry_unavailable", "release registry is not configured")
		return
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 && parts[0] == "publish" {
		h.handleReleasePublish(w, r)
		return
	}
	if len(parts) == 2 && parts[0] == "agent-types" && parts[1] != "" {
		h.handleReleaseRollback(w, r, parts[1])
		return
	}
	if len(parts) == 2 {
		generation, err := strconv.ParseInt(parts[0], 10, 64)
		if err == nil && generation > 0 {
			switch parts[1] {
			case "verify":
				h.handleReleaseVerify(w, r, generation)
				return
			case "acquire":
				h.handleReleaseAcquire(w, r, generation)
				return
			case "promote":
				h.handleReleasePromote(w, r, generation)
				return
			}
		}
	}
	writeRESTError(w, http.StatusNotFound, "not_found")
}

func (h *restHandler) handleReleasePublish(w http.ResponseWriter, r *http.Request) {
	const operation = "release.publish"
	if !requirePOST(w, r) {
		return
	}
	promoter, ok := h.authenticatePromoter(w, r, operation)
	if !ok || !h.authorizePromoterAction(w, promoter, operation) {
		return
	}
	var input publishReleaseRequest
	if !decodeReleaseRequest(w, r, h.service.cfg.MaxParameterBytes, &input) {
		return
	}
	item, err := h.releases.PublishCandidate(r.Context(), input.AgentType, input.ImageReference, input.Provenance, promoter.Name)
	if err != nil {
		h.writeReleaseError(w, operation, promoter.Name, err)
		return
	}
	h.audit(operation, promoter.Name, "", "", "", "", "", "allow", nil, nil)
	writeJSON(w, http.StatusCreated, item)
}

func (h *restHandler) handleReleaseVerify(w http.ResponseWriter, r *http.Request, generation int64) {
	const operation = "release.verify"
	if !requirePOST(w, r) {
		return
	}
	promoter, ok := h.authenticatePromoter(w, r, operation)
	if !ok || !h.authorizePromoterAction(w, promoter, operation) {
		return
	}
	var input verifyReleaseRequest
	if !decodeReleaseRequest(w, r, h.service.cfg.MaxParameterBytes, &input) {
		return
	}
	if err := h.releases.Verify(r.Context(), generation, input.Requirements, promoter.Name); err != nil {
		h.writeReleaseError(w, operation, promoter.Name, err)
		return
	}
	h.audit(operation, promoter.Name, "", "", "", "", "", "allow", nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *restHandler) handleReleaseAcquire(w http.ResponseWriter, r *http.Request, generation int64) {
	const operation = "release.acquire"
	if !requirePOST(w, r) {
		return
	}
	promoter, ok := h.authenticatePromoter(w, r, operation)
	if !ok || !h.authorizePromoterAction(w, promoter, operation) {
		return
	}
	if !decodeReleaseRequest(w, r, h.service.cfg.MaxParameterBytes, &struct{}{}) {
		return
	}
	if err := h.releases.MarkAvailable(r.Context(), generation, true, promoter.Name); err != nil {
		h.writeReleaseError(w, operation, promoter.Name, err)
		return
	}
	h.audit(operation, promoter.Name, "", "", "", "", "", "allow", nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *restHandler) handleReleasePromote(w http.ResponseWriter, r *http.Request, generation int64) {
	const operation = "release.promote"
	if !requirePOST(w, r) {
		return
	}
	promoter, ok := h.authenticatePromoter(w, r, operation)
	if !ok || !h.authorizePromoterAction(w, promoter, operation) {
		return
	}
	if !decodeReleaseRequest(w, r, h.service.cfg.MaxParameterBytes, &struct{}{}) {
		return
	}
	if err := h.releases.Promote(r.Context(), generation, promoter.Name); err != nil {
		h.writeReleaseError(w, operation, promoter.Name, err)
		return
	}
	h.audit(operation, promoter.Name, "", "", "", "", "", "allow", nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *restHandler) handleReleaseRollback(w http.ResponseWriter, r *http.Request, agentType string) {
	const operation = "release.rollback"
	if !requirePOST(w, r) {
		return
	}
	promoter, ok := h.authenticatePromoter(w, r, operation)
	if !ok || !h.authorizePromoterAction(w, promoter, operation) {
		return
	}
	var input rollbackReleaseRequest
	if !decodeReleaseRequest(w, r, h.service.cfg.MaxParameterBytes, &input) {
		return
	}
	if err := h.releases.Rollback(r.Context(), agentType, input.Generation, promoter.Name); err != nil {
		h.writeReleaseError(w, operation, promoter.Name, err)
		return
	}
	h.audit(operation, promoter.Name, "", "", "", "", "", "allow", nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *restHandler) authenticatePromoter(w http.ResponseWriter, r *http.Request, operation string) (VerifiedPromoter, bool) {
	promoter, err := h.promoterAuth.AuthenticatePromoter(r)
	if err == nil {
		return promoter, true
	}
	h.audit(operation, "", "", "", "", "", "", "deny", err, nil)
	writeRESTError(w, http.StatusUnauthorized, "unauthorized")
	return VerifiedPromoter{}, false
}

func (h *restHandler) authorizePromoterAction(w http.ResponseWriter, promoter VerifiedPromoter, operation string) bool {
	if contains(promoter.Principal.AllowedActions, operation) {
		return true
	}
	err := errors.New("forbidden")
	h.audit(operation, promoter.Name, "", "", "", "", "", "deny", err, nil)
	writeRESTError(w, http.StatusForbidden, "forbidden")
	return false
}

func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodPost {
		return true
	}
	writeRESTError(w, http.StatusMethodNotAllowed, "method_not_allowed")
	return false
}

func decodeReleaseRequest(w http.ResponseWriter, r *http.Request, maxBytes int, output any) bool {
	defer closeBody(r.Body)
	if maxBytes < 1 {
		maxBytes = defaultMaxParamBytes
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBytes)+1))
	if err == nil && len(b) > maxBytes {
		err = fmt.Errorf("request body exceeds max_parameter_bytes %d", maxBytes)
	}
	if err == nil && len(bytes.TrimSpace(b)) == 0 {
		b = []byte("{}")
	}
	if err == nil {
		decoder := json.NewDecoder(bytes.NewReader(b))
		err = decoder.Decode(output)
		if err == nil {
			var extra any
			if decodeErr := decoder.Decode(&extra); !errors.Is(decodeErr, io.EOF) {
				if decodeErr == nil {
					err = errors.New("request body must contain exactly one JSON value")
				} else {
					err = decodeErr
				}
			}
		}
	}
	if err == nil {
		return true
	}
	writeRESTError(w, http.StatusBadRequest, err.Error())
	return false
}

func (h *restHandler) writeReleaseError(w http.ResponseWriter, operation, actor string, err error) {
	h.audit(operation, actor, "", "", "", "", "", "deny", err, nil)
	status := http.StatusBadRequest
	code := "release_operation_failed"
	switch {
	case errors.Is(err, release.ErrNotFound):
		status, code = http.StatusNotFound, "release_not_found"
	case errors.Is(err, release.ErrNoActiveRelease):
		status, code = http.StatusConflict, "no_active_release"
	case errors.Is(err, release.ErrUnavailable):
		status, code = http.StatusConflict, "release_unavailable"
	case errors.Is(err, release.ErrNotPromotable):
		status, code = http.StatusConflict, "release_not_promotable"
	case errors.Is(err, release.ErrNotMonotonic):
		status, code = http.StatusConflict, "release_not_monotonic"
	}
	writeRESTCodeError(w, status, code, err.Error())
}
