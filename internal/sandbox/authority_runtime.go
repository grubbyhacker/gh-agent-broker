package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DockerAuthorityRuntime is purpose-built for immutable authority workers. It
// does not accept caller runtime inputs; AuthorityWorkerSpec is constructed
// exclusively from a reviewed profile.
type DockerAuthorityRuntime struct {
	docker     *DockerBackend
	profiles   map[string]AuthorityProfile
	httpClient *http.Client
}

func NewDockerAuthorityRuntime(socket string, cfg Config) *DockerAuthorityRuntime {
	return &DockerAuthorityRuntime{docker: NewDockerBackend(socket), profiles: cfg.AuthorityProfiles, httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func (r *DockerAuthorityRuntime) Create(ctx context.Context, spec AuthorityWorkerSpec) (AuthorityRuntimeResult, error) {
	secret := strings.TrimSpace(os.Getenv(spec.BrokerSecretEnv))
	if secret == "" {
		return AuthorityRuntimeResult{}, fmt.Errorf("authority worker broker credential is unavailable")
	}
	coordinatorToken := strings.TrimSpace(os.Getenv(spec.CoordinatorTokenEnv))
	if coordinatorToken == "" {
		return AuthorityRuntimeResult{}, fmt.Errorf("authority worker coordinator credential is unavailable")
	}
	if !validOpaqueLineageID(spec.WorkerStorageLineageID) || spec.WorkerFenceEpoch < 1 {
		return AuthorityRuntimeResult{}, fmt.Errorf("authority worker storage lineage identity is invalid")
	}
	volumes := []Mount{
		{Source: spec.Storage.SessionVolume, Target: spec.SessionIsolation.WorkspaceRoot, Volume: true, VolumeSubpath: spec.WorkerStorageLineageID},
		{Source: spec.Storage.CheckpointVolume, Target: spec.Checkpoint.Directory, Volume: true, VolumeSubpath: spec.WorkerStorageLineageID},
		{Source: spec.Storage.EvidenceVolume, Target: "/var/lib/agentd/evidence", Volume: true, VolumeSubpath: spec.WorkerStorageLineageID},
	}
	if err := r.docker.EnsureVolumeSubpaths(ctx, spec.Image, spec.WorkerStorageLineageID, volumes); err != nil {
		return AuthorityRuntimeResult{}, fmt.Errorf("prepare authority worker volume subpaths: %w", err)
	}
	mounts := append([]Mount(nil), volumes...)
	if spec.CredentialBundle != "" {
		mounts = append(mounts, spec.CredentialMount)
	}
	for _, mount := range spec.ExtraMounts {
		mounts = append(mounts, Mount{Source: mount.SourcePath, Target: mount.MountPath, ReadOnly: mount.ReadOnly})
	}
	runtimeSpec := authorityWorkerRuntimeSpec(spec, secret, coordinatorToken, mounts)
	info, err := r.docker.Create(ctx, runtimeSpec)
	if err != nil {
		return AuthorityRuntimeResult{}, err
	}
	if !info.Existing && info.Lifecycle == ContainerNeverStarted {
		if err := r.docker.Start(ctx, info.ID); err != nil {
			return AuthorityRuntimeResult{}, err
		}
	}
	return AuthorityRuntimeResult{ContainerID: info.ID, ImageDigest: imageDigestOnly(info.ImageDigest)}, nil
}

func authorityWorkerRuntimeSpec(spec AuthorityWorkerSpec, secret, coordinatorToken string, mounts []Mount) RuntimeSpec {
	// Keep agentd's OCI WORKDIR (/app): the immutable entrypoint references
	// source relative to that directory. State is durable within the worker's
	// engine-enforced storage-lineage subpath.
	env := map[string]string{
		spec.BrokerSecretEnv:        secret,
		"AGENTD_COORDINATOR_TOKEN":  coordinatorToken,
		"AGENTD_STATE_PATH":         filepath.Join(spec.SessionIsolation.WorkspaceRoot, "agentd.sqlite3"),
		"AGENTD_WORKER_ID":          spec.WorkerID,
		"AGENTD_STORAGE_LINEAGE_ID": spec.WorkerStorageLineageID,
		"AGENTD_FENCE_EPOCH":        strconv.FormatInt(spec.WorkerFenceEpoch, 10),
		"AGENTD_AUTHORITY_BINDING":  spec.Profile,
		"AGENTD_SESSION_ROOT":       spec.SessionIsolation.WorkspaceRoot,
		"AGENTD_SESSION_UID_MIN":    strconv.Itoa(spec.SessionIsolation.UIDStart),
		"AGENTD_SESSION_CAPACITY":   strconv.Itoa(spec.SessionCapacity),
	}
	labels := map[string]string{
		"gh-agent-broker.run_id":                 "authority-" + spec.WorkerID,
		"gh-agent-broker.authority_worker":       "true",
		"gh-agent-broker.worker_id":              spec.WorkerID,
		"gh-agent-broker.worker_storage_lineage": spec.WorkerStorageLineageID,
		"gh-agent-broker.worker_fence_epoch":     strconv.FormatInt(spec.WorkerFenceEpoch, 10),
		"gh-agent-broker.profile":                spec.Profile,
		"gh-agent-broker.profile_version":        spec.ProfileVersion,
		"gh-agent-broker.policy_digest":          spec.PolicyDigest,
		"gh-agent-broker.session_isolation":      spec.SessionIsolation.Primitive,
	}
	return RuntimeSpec{
		RunID:      "authority-" + spec.WorkerID,
		Image:      spec.Image,
		Platform:   spec.Platform,
		Entrypoint: append([]string(nil), spec.Command...),
		// Keep the agentd server non-root. The reviewed image's immutable,
		// root-owned setuid launcher is the only process allowed to transition
		// privileges, so this spec alone omits no-new-privileges.
		User:      "bun",
		Env:       env,
		Labels:    labels,
		Mounts:    mounts,
		Network:   spec.Network,
		Resources: spec.Resources,
		AllowAgentdSetuidLauncherPrivilegeTransition: true,
	}
}

func (r *DockerAuthorityRuntime) Stop(ctx context.Context, id string) error {
	err := r.docker.Stop(ctx, id, 10)
	if status, ok := DockerStatusCode(err); ok && status == 304 {
		return nil
	}
	return err
}

func (r *DockerAuthorityRuntime) Healthy(ctx context.Context, id string) (bool, string, error) {
	status, err := r.docker.Inspect(ctx, id)
	if err != nil {
		return false, "runtime_inspect_failed", err
	}
	if !status.Running {
		return false, "container_not_running", nil
	}
	return true, "container_liveness_ok", nil
}

type agentdReadinessResponse struct {
	Version          string   `json:"version"`
	Status           string   `json:"status"`
	Reasons          []string `json:"reasons"`
	WorkerID         string   `json:"workerId"`
	StorageLineageID string   `json:"storageLineageId"`
	FenceEpoch       int64    `json:"fenceEpoch"`
	Components       struct {
		Journal   bool `json:"journal"`
		Runtime   bool `json:"runtime"`
		Launcher  bool `json:"launcher"`
		Isolation bool `json:"isolation"`
	} `json:"components"`
}

// AgentdReady authenticates the versioned readiness endpoint and validates
// every worker-generation identity and subsystem claim. Any mismatch is a
// closed readiness result, never container liveness.
func (r *DockerAuthorityRuntime) AgentdReady(ctx context.Context, worker AuthorityWorker) (bool, string, error) {
	profile, ok := r.profiles[worker.Profile]
	readiness := configuredAgentdReadiness(profile)
	if !ok || readiness.ContractVersion != "agentd/control/v1" {
		return false, "agentd_readiness_profile_unavailable", nil
	}
	token := strings.TrimSpace(os.Getenv(profile.CoordinatorTokenEnv))
	if token == "" {
		return false, "agentd_readiness_credential_unavailable", nil
	}
	address, err := r.docker.InternalAddress(ctx, worker.ContainerID)
	if err != nil || address == "" {
		return false, "agentd_internal_address_unavailable", err
	}
	url := "http://" + address + ":" + strconv.Itoa(readiness.Port) + readiness.Path
	//nolint:gosec // The host is Docker's inspected address for this worker; port and exact /readyz path are operator-reviewed profile fields.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, "agentd_readiness_request_invalid", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return probeAgentdReadiness(r.httpClient, req, readiness.ContractVersion, worker)
}

func probeAgentdReadiness(client *http.Client, req *http.Request, protocolVersion string, worker AuthorityWorker) (bool, string, error) {
	//nolint:gosec // Callers construct the request only from the inspected worker address and reviewed readiness profile above.
	resp, err := client.Do(req)
	if err != nil {
		return false, "agentd_readiness_unavailable", nil
	}
	defer closeBody(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		return false, "agentd_readiness_rejected", nil
	}
	var claim agentdReadinessResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claim); err != nil {
		return false, "agentd_readiness_malformed", nil
	}
	if claim.Version != protocolVersion || claim.WorkerID != worker.WorkerID || claim.StorageLineageID != worker.WorkerStorageLineageID || claim.FenceEpoch != worker.WorkerFenceEpoch {
		return false, "agentd_readiness_identity_mismatch", nil
	}
	componentsReady := claim.Components.Journal && claim.Components.Runtime && claim.Components.Launcher && claim.Components.Isolation
	if resp.StatusCode != http.StatusOK || claim.Status != "ready" || len(claim.Reasons) != 0 || !componentsReady {
		return false, "agentd_readiness_subsystem_unavailable", nil
	}
	return true, "agentd_authenticated_readiness_ok", nil
}

func imageDigestOnly(value string) string {
	if index := strings.LastIndex(value, "@sha256:"); index >= 0 {
		return value[index+1:]
	}
	if strings.HasPrefix(value, "sha256:") {
		return value
	}
	return ""
}
