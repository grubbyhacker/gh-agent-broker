package sandbox

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// DockerAuthorityRuntime is purpose-built for immutable authority workers. It
// does not accept caller runtime inputs; AuthorityWorkerSpec is constructed
// exclusively from a reviewed profile.
type DockerAuthorityRuntime struct{ docker *DockerBackend }

func NewDockerAuthorityRuntime(socket string) *DockerAuthorityRuntime {
	return &DockerAuthorityRuntime{docker: NewDockerBackend(socket)}
}

func (r *DockerAuthorityRuntime) Create(ctx context.Context, spec AuthorityWorkerSpec) (AuthorityRuntimeResult, error) {
	secret := strings.TrimSpace(os.Getenv(spec.BrokerSecretEnv))
	if secret == "" {
		return AuthorityRuntimeResult{}, fmt.Errorf("authority worker broker credential is unavailable")
	}
	mounts := []Mount{{Source: spec.Storage.SessionVolume, Target: spec.SessionIsolation.WorkspaceRoot, ReadOnly: false}, {Source: spec.Storage.CheckpointVolume, Target: spec.Checkpoint.Directory, ReadOnly: false}, {Source: spec.Storage.EvidenceVolume, Target: "/var/lib/agentd/evidence", ReadOnly: false}}
	if spec.CredentialBundle != "" {
		mounts = append(mounts, spec.CredentialMount)
	}
	for _, mount := range spec.ExtraMounts {
		mounts = append(mounts, Mount{Source: mount.SourcePath, Target: mount.MountPath, ReadOnly: mount.ReadOnly})
	}
	runtimeSpec := RuntimeSpec{RunID: "authority-" + spec.WorkerID, Image: spec.Image, Command: spec.Command, Env: map[string]string{spec.BrokerSecretEnv: secret}, Labels: map[string]string{"gh-agent-broker.authority_worker": "true", "gh-agent-broker.worker_id": spec.WorkerID, "gh-agent-broker.profile": spec.Profile, "gh-agent-broker.profile_version": spec.ProfileVersion, "gh-agent-broker.policy_digest": spec.PolicyDigest, "gh-agent-broker.session_isolation": spec.SessionIsolation.Primitive}, Mounts: mounts, Network: spec.Network, Resources: spec.Resources, WorkingDir: "/var/lib/agentd"}
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

func (r *DockerAuthorityRuntime) Stop(ctx context.Context, id string) error {
	return r.docker.Stop(ctx, id, 10)
}

func (r *DockerAuthorityRuntime) Healthy(ctx context.Context, id string) (bool, string, error) {
	status, err := r.docker.Inspect(ctx, id)
	if err != nil {
		return false, "runtime_inspect_failed", err
	}
	if !status.Running {
		return false, "container_not_running", nil
	}
	return true, "container_liveness_ok_agentd_session_admission_deferred", nil
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
