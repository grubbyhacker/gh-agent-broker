package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"

	"gh-agent-broker/internal/release"
)

// ReleaseRegistry is the narrow registry surface exposed through REST.
// Authentication is intentionally not part of this interface.
type ReleaseRegistry interface {
	PublishCandidate(context.Context, string, string, release.Provenance, string) (release.Release, error)
	VerifyAndMarkAvailable(context.Context, int64, release.Requirements, string, string, func(context.Context, release.Release) error) error
	Get(context.Context, int64) (release.Release, error)
	Promote(context.Context, int64, string) error
	Rollback(context.Context, string, int64, string) error
}

type publishReleaseRequest struct {
	AgentType  string             `json:"agent_type"`
	Provenance release.Provenance `json:"provenance"`
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
	if len(parts) == 2 && parts[1] == "promote" {
		if generation, err := parseReleaseGeneration(parts[0]); err == nil && generation > 0 {
			h.handleReleasePromote(w, r, generation)
			return
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
	input, artifact, ok := decodeReleasePublishRequest(w, r, h.service.cfg.ReleaseArtifactByteLimit)
	if !ok {
		return
	}
	policy, policyFound := h.service.cfg.AgentReleasePolicies[input.AgentType]
	if !policyFound {
		h.writeReleaseError(w, operation, promoter.Name, errors.New("agent type has no deployment-owned release policy"))
		return
	}
	imageID, err := validateDockerArtifact(artifact, input.Provenance.Platform)
	if err != nil {
		h.writeReleaseError(w, operation, promoter.Name, err)
		return
	}
	imageReference := "local.agent/" + input.AgentType + "@" + imageID
	item, err := h.releases.PublishCandidate(r.Context(), input.AgentType, imageReference, input.Provenance, promoter.Name)
	if err != nil {
		h.writeReleaseError(w, operation, promoter.Name, err)
		return
	}
	importer, importerOK := h.releaseImporter()
	if !importerOK {
		h.writeReleaseError(w, operation, promoter.Name, errors.New("release artifact importer is unavailable"))
		return
	}
	requirements := release.Requirements{ProvenanceFields: policy.ProvenanceFields, Platforms: policy.Platforms}
	if err := h.releases.VerifyAndMarkAvailable(r.Context(), item.Generation, requirements, "sandbox-broker-verifier", "sandbox-broker-acquirer", func(ctx context.Context, candidate release.Release) error {
		return acquireDockerArtifact(ctx, importer, artifact, candidate, imageID)
	}); err != nil {
		h.writeReleaseError(w, operation, promoter.Name, err)
		return
	}
	ready, err := h.releases.Get(r.Context(), item.Generation)
	if err != nil {
		h.writeReleaseError(w, operation, promoter.Name, err)
		return
	}
	h.audit(operation, promoter.Name, "", "", "", "", "", "allow", nil, nil)
	writeJSON(w, http.StatusCreated, ready)
}

func parseReleaseGeneration(value string) (int64, error) {
	var generation int64
	_, err := fmt.Sscan(value, &generation)
	return generation, err
}

func (h *restHandler) releaseImporter() (releaseArtifactImporter, bool) {
	importer, ok := h.service.runtime.(releaseArtifactImporter)
	return importer, ok
}

func decodeReleasePublishRequest(w http.ResponseWriter, r *http.Request, maxBytes int) (publishReleaseRequest, []byte, bool) {
	defer closeBody(r.Body)
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		writeRESTError(w, http.StatusBadRequest, "release publish requires multipart/form-data")
		return publishReleaseRequest{}, nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes)+1)
	reader := multipart.NewReader(r.Body, params["boundary"])
	var input publishReleaseRequest
	var artifact []byte
	seen := map[string]bool{}
	for {
		part, nextErr := reader.NextPart()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			writeRESTError(w, http.StatusBadRequest, nextErr.Error())
			return publishReleaseRequest{}, nil, false
		}
		name := part.FormName()
		if seen[name] || (name != "protocol" && name != "metadata" && name != "artifact") {
			writeRESTError(w, http.StatusBadRequest, "release publish has duplicate or unknown part")
			return publishReleaseRequest{}, nil, false
		}
		seen[name] = true
		b, readErr := io.ReadAll(io.LimitReader(part, int64(maxBytes)+1))
		if readErr != nil || len(b) > maxBytes {
			writeRESTError(w, http.StatusBadRequest, "release artifact exceeds release_artifact_byte_limit")
			return publishReleaseRequest{}, nil, false
		}
		switch name {
		case "protocol":
			if string(b) != releasePublishProtocol {
				writeRESTError(w, http.StatusBadRequest, "unsupported release publish protocol")
				return publishReleaseRequest{}, nil, false
			}
		case "metadata":
			if json.Unmarshal(b, &input) != nil {
				writeRESTError(w, http.StatusBadRequest, "invalid release publish metadata")
				return publishReleaseRequest{}, nil, false
			}
		case "artifact":
			artifact = b
		}
	}
	if !seen["protocol"] || !seen["metadata"] || !seen["artifact"] || len(artifact) == 0 {
		writeRESTError(w, http.StatusBadRequest, "release publish requires protocol, metadata, and artifact")
		return publishReleaseRequest{}, nil, false
	}
	return input, artifact, true
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
