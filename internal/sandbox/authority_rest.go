package sandbox

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// NewAuthorityRESTHandler exposes broker lifecycle and authority-lease controls.
// It never accepts caller-selected runtime, repository, or policy fields.
func NewAuthorityRESTHandler(service *AuthorityWorkerService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/authority-workers"), "/")
		if r.Method == http.MethodPost && path == "agentd/session-validation" {
			var in AgentdSessionValidationRequest
			if !decodeAuthorityJSON(w, r, &in) {
				return
			}
			out, err := service.ValidateAgentdSession(r.Context(), bearerToken(r), in)
			if err != nil {
				writeRESTCodeError(w, http.StatusInternalServerError, "validation_failed", err.Error())
				return
			}
			if !out.Authorized {
				writeJSON(w, http.StatusForbidden, out)
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		principal, ok := authorityRESTPrincipal(service.cfg, bearerToken(r))
		if !ok {
			writeRESTError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if r.Method == http.MethodPost && path == "coordinator/v1/leases" {
			var in AuthorityWorkerRequest
			if !decodeAuthorityJSON(w, r, &in) {
				return
			}
			out, err := service.AcquireSession(r.Context(), principal, in)
			if err != nil {
				writeRESTCodeError(w, http.StatusConflict, "lease_denied", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, CoordinatorLeaseAdmission{Version: coordinatorProtocolVersion, Admission: out})
			return
		}
		if r.Method == http.MethodPost && path == "coordinator/v2/leases" {
			var in RegisteredAdmissionRequest
			if !decodeAuthorityJSON(w, r, &in) {
				return
			}
			out, err := service.AcquireRegisteredSession(r.Context(), principal, in)
			if err != nil {
				writeRESTCodeError(w, http.StatusConflict, "registered_lease_denied", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, CoordinatorLeaseAdmission{Version: coordinatorRegisteredProtocolVersion, Admission: out})
			return
		}
		if r.Method == http.MethodPost && strings.HasPrefix(path, "coordinator/v1/sessions/") {
			operation := strings.TrimPrefix(path, "coordinator/v1/sessions/")
			var in CoordinatorSessionRequest
			if !decodeAuthorityJSON(w, r, &in) {
				return
			}
			if operation == "create" {
				if err := validateCoordinatorSessionRequest("status", in); err != nil {
					writeRESTCodeError(w, http.StatusBadRequest, "invalid_session_command", err.Error())
					return
				}
				result, err := service.CreateSession(r.Context(), principal, in.SessionBinding)
				if err != nil {
					writeRESTCodeError(w, http.StatusConflict, "session_create_denied", err.Error())
					return
				}
				lease, err := service.store.GetLease(r.Context(), principal, in.SessionBinding)
				if err != nil {
					writeRESTCodeError(w, http.StatusConflict, "session_create_denied", "session lease unavailable")
					return
				}
				writeJSON(w, http.StatusCreated, CoordinatorSessionResponse{Version: coordinatorProtocolVersion, Lease: lease, Result: result})
				return
			}
			out, err := service.CoordinatorSessionCommand(r.Context(), principal, operation, in)
			if err != nil {
				var agentdErr *CoordinatorAgentdError
				if errors.As(err, &agentdErr) {
					writeRESTCodeError(w, agentdErr.Status, agentdErr.Code, agentdErr.Error())
					return
				}
				writeRESTCodeError(w, http.StatusConflict, "session_command_denied", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		if r.Method == http.MethodPost && path == "coordinator/v1/reassign" {
			var in AuthoritySessionReassignmentRequest
			if !decodeAuthorityJSON(w, r, &in) {
				return
			}
			out, err := service.ReassignSession(r.Context(), principal, in)
			if err != nil {
				authorityReassignmentError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, struct {
				Version      string                       `json:"version"`
				Reassignment AuthoritySessionReassignment `json:"reassignment"`
			}{coordinatorProtocolVersion, out})
			return
		}
		if r.Method == http.MethodPost && path == "coordinator/v1/reassignments/status" {
			var in struct {
				SessionBinding        string `json:"session_binding"`
				PredecessorFenceEpoch int64  `json:"predecessor_fence_epoch"`
			}
			if !decodeAuthorityJSON(w, r, &in) {
				return
			}
			out, err := service.CoordinatorReassignmentStatus(r.Context(), principal, in.SessionBinding, in.PredecessorFenceEpoch)
			if err != nil {
				writeRESTCodeError(w, http.StatusNotFound, "reassignment_status_unavailable", "reassignment status unavailable")
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		if r.Method == http.MethodPost && path == "provision" {
			var in struct {
				Profile string `json:"profile"`
			}
			if !decodeAuthorityJSON(w, r, &in) {
				return
			}
			out, err := service.Provision(r.Context(), principal, in.Profile)
			authorityResponse(w, out, err)
			return
		}
		if r.Method == http.MethodPost && path == "reconcile" {
			if err := service.Reconcile(r.Context(), principal); err != nil {
				writeRESTCodeError(w, http.StatusConflict, "reconcile_failed", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "reconciled"})
			return
		}
		if r.Method == http.MethodPost && path == "leases" {
			var in AuthorityWorkerRequest
			if !decodeAuthorityJSON(w, r, &in) {
				return
			}
			out, err := service.AcquireSession(r.Context(), principal, in)
			if err != nil {
				writeRESTCodeError(w, http.StatusConflict, "lease_denied", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		if r.Method == http.MethodPost && path == "leases/release" {
			var in struct {
				SessionBinding string `json:"session_binding"`
			}
			if !decodeAuthorityJSON(w, r, &in) {
				return
			}
			out, err := service.Release(r.Context(), principal, in.SessionBinding)
			if err != nil {
				writeRESTCodeError(w, http.StatusConflict, "lease_denied", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		if r.Method == http.MethodPost && path == "leases/reassign" {
			var in AuthoritySessionReassignmentRequest
			if !decodeAuthorityJSON(w, r, &in) {
				return
			}
			out, err := service.ReassignSession(r.Context(), principal, in)
			if err != nil {
				authorityReassignmentError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		if strings.HasPrefix(path, "leases/") && strings.HasSuffix(path, "/sessions") && r.Method == http.MethodPost {
			binding := strings.TrimSuffix(strings.TrimPrefix(path, "leases/"), "/sessions")
			out, err := service.CreateSession(r.Context(), principal, binding)
			if err != nil {
				writeRESTCodeError(w, http.StatusConflict, "session_create_denied", err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, out)
			return
		}
		parts := strings.Split(path, "/")
		if len(parts) == 1 && r.Method == http.MethodGet && parts[0] != "" {
			out, err := service.GetWorker(r.Context(), principal, parts[0])
			authorityResponse(w, out, err)
			return
		}
		if len(parts) == 2 && r.Method == http.MethodPost {
			id, action := parts[0], parts[1]
			switch action {
			case "health":
				var in struct {
					Healthy  bool   `json:"healthy"`
					Evidence string `json:"evidence"`
				}
				if !decodeAuthorityJSON(w, r, &in) {
					return
				}
				out, err := service.SetHealth(r.Context(), principal, id, in.Evidence, in.Healthy)
				authorityResponse(w, out, err)
				return
			case "drain":
				var in struct {
					Reason string `json:"reason"`
				}
				if !decodeAuthorityJSON(w, r, &in) {
					return
				}
				out, err := service.Drain(r.Context(), principal, id, in.Reason)
				authorityResponse(w, out, err)
				return
			case "replace":
				var in struct {
					Reason string `json:"reason"`
				}
				if !decodeAuthorityJSON(w, r, &in) {
					return
				}
				out, err := service.Replace(r.Context(), principal, id, in.Reason)
				authorityResponse(w, out, err)
				return
			}
		}
		writeRESTError(w, http.StatusNotFound, "not_found")
	})
}

func authorityReassignmentError(w http.ResponseWriter, err error) {
	var reassignmentErr *ReassignmentError
	if errors.As(err, &reassignmentErr) {
		status := http.StatusConflict
		if reassignmentErr.Code == ReassignmentRebindRetryable {
			status = http.StatusServiceUnavailable
		}
		writeRESTCodeError(w, status, string(reassignmentErr.Code), reassignmentErr.Error())
		return
	}
	writeRESTCodeError(w, http.StatusConflict, "reassignment_denied", err.Error())
}

func authorityRESTPrincipal(cfg Config, token string) (string, bool) {
	for name, p := range cfg.AuthorityPrincipals {
		if secureTokenEqual(token, p.Token) {
			return name, true
		}
	}
	return "", false
}

func decodeAuthorityJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		writeRESTError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func authorityResponse(w http.ResponseWriter, out AuthorityWorker, err error) {
	if err != nil {
		writeRESTCodeError(w, http.StatusConflict, "lifecycle_denied", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
