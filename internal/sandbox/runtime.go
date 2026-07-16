package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type RuntimeBackend interface {
	Create(ctx context.Context, spec RuntimeSpec) (ContainerInfo, error)
	Start(ctx context.Context, containerID string) error
	Wait(ctx context.Context, containerID string) (ContainerStatus, error)
	Inspect(ctx context.Context, containerID string) (ContainerStatus, error)
	Logs(ctx context.Context, containerID string, limitBytes int) (string, error)
	Stop(ctx context.Context, containerID string, grace time.Duration) error
	Remove(ctx context.Context, containerID string) error
}

type RuntimeSpec struct {
	RunID      string
	Image      string
	Platform   string
	Entrypoint []string
	Command    []string
	User       string
	Env        map[string]string
	Labels     map[string]string
	Mounts     []Mount
	Network    NetworkPolicy
	Resources  Resources
	WorkingDir string
	Timeout    time.Duration
	// AllowAgentdSetuidLauncherPrivilegeTransition is the sole exception to
	// Docker's default no-new-privileges policy. It is set only by the reviewed
	// authority-worker spec: agentd stays the non-root bun user while its fixed,
	// root-owned setuid launcher obtains the euid required to isolate a turn.
	AllowAgentdSetuidLauncherPrivilegeTransition bool
}

type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
	Volume   bool
	// VolumeSubpath selects an existing relative directory inside a named
	// Docker volume. It is never represented as a bind string.
	VolumeSubpath string
}

type ContainerInfo struct {
	ID          string
	ImageDigest string
	Existing    bool
	Lifecycle   ContainerLifecycle
	Status      ContainerStatus
}

type ContainerLifecycle string

const (
	ContainerNeverStarted ContainerLifecycle = "never_started"
	ContainerRunning      ContainerLifecycle = "running"
	ContainerExited       ContainerLifecycle = "exited"
)

type ContainerStatus struct {
	ID        string
	Running   bool
	ExitCode  *int
	StartedAt time.Time
	EndedAt   time.Time
	Error     string
}

type DockerBackend struct {
	socket string
	client *http.Client
}

func NewDockerBackend(socket string) *DockerBackend {
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &DockerBackend{socket: socket, client: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
}

func (d *DockerBackend) Create(ctx context.Context, spec RuntimeSpec) (ContainerInfo, error) {
	spec.Labels = cloneStringMap(spec.Labels)
	specDigest, err := runtimeSpecDigest(spec)
	if err != nil {
		return ContainerInfo{}, fmt.Errorf("fingerprint sandbox runtime spec: %w", err)
	}
	spec.Labels["gh-agent-broker.launch_spec"] = specDigest
	imageDigest, err := d.imageDigest(ctx, spec.Image)
	if err != nil {
		imageDigest = spec.Image
	}
	reqBody := dockerCreateRequest{
		Image:      spec.Image,
		Platform:   spec.Platform,
		Entrypoint: spec.Entrypoint,
		Cmd:        spec.Command,
		User:       spec.User,
		Env:        envList(spec.Env),
		Labels:     spec.Labels,
		WorkingDir: spec.WorkingDir,
		HostConfig: dockerHostConfig{
			ReadonlyRootfs:  false,
			SecurityOpt:     runtimeSecurityOptions(spec),
			CapDrop:         []string{"ALL"},
			NetworkMode:     networkMode(spec.Network),
			Binds:           binds(spec.Mounts),
			Mounts:          dockerMounts(spec.Mounts),
			PidsLimit:       spec.Resources.PidsLimit,
			Memory:          spec.Resources.MemoryMB * 1024 * 1024,
			CPUWeight:       spec.Resources.CPUShares,
			AutoRemove:      false,
			Privileged:      false,
			PublishAllPorts: false,
		},
	}
	var out struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	path := "/containers/create?name=" + url.QueryEscape("sandbox-"+spec.RunID)
	if err := d.doJSON(ctx, http.MethodPost, path, reqBody, &out); err != nil {
		if code, ok := DockerStatusCode(err); ok && code == http.StatusConflict {
			return d.adopt(ctx, spec)
		}
		return ContainerInfo{}, err
	}
	return ContainerInfo{ID: out.ID, ImageDigest: imageDigest, Lifecycle: ContainerNeverStarted}, nil
}

func runtimeSecurityOptions(spec RuntimeSpec) []string {
	if spec.AllowAgentdSetuidLauncherPrivilegeTransition {
		return nil
	}
	return []string{"no-new-privileges"}
}

func (d *DockerBackend) adopt(ctx context.Context, spec RuntimeSpec) (ContainerInfo, error) {
	name := "sandbox-" + spec.RunID
	var out dockerInspectResponse
	if err := d.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &out); err != nil {
		return ContainerInfo{}, fmt.Errorf("inspect colliding sandbox container: %w", err)
	}
	wantDigest, err := runtimeSpecDigest(spec)
	if err != nil {
		return ContainerInfo{}, fmt.Errorf("fingerprint sandbox runtime spec: %w", err)
	}
	if out.Name != "/"+name || out.Config.Labels["gh-agent-broker.run_id"] != spec.RunID ||
		out.Config.Labels["gh-agent-broker.launch_spec"] != wantDigest {
		return ContainerInfo{}, fmt.Errorf("sandbox container name collision for run %q does not exactly match durable launch intent", spec.RunID)
	}
	status := dockerContainerStatus(out)
	lifecycle := ContainerExited
	if status.StartedAt.IsZero() {
		lifecycle = ContainerNeverStarted
	} else if status.Running {
		lifecycle = ContainerRunning
	}
	return ContainerInfo{ID: out.ID, ImageDigest: out.Image, Existing: true, Lifecycle: lifecycle, Status: status}, nil
}

func (d *DockerBackend) Start(ctx context.Context, containerID string) error {
	return d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerID)+"/start", nil, nil)
}

func (d *DockerBackend) Wait(ctx context.Context, containerID string) (ContainerStatus, error) {
	path := "/containers/" + url.PathEscape(containerID) + "/wait?condition=not-running"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker"+path, nil)
	if err != nil {
		return ContainerStatus{}, err
	}
	waitClient := *d.client
	waitClient.Timeout = 0
	resp, err := waitClient.Do(req)
	if err != nil {
		return ContainerStatus{}, err
	}
	defer closeBody(resp.Body)
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ContainerStatus{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ContainerStatus{}, DockerError{Method: http.MethodPost, Path: path, StatusCode: resp.StatusCode, Body: string(b)}
	}
	var out dockerWaitResponse
	if len(b) > 0 {
		if err := json.Unmarshal(b, &out); err != nil {
			return ContainerStatus{}, err
		}
	}
	status, err := d.Inspect(ctx, containerID)
	if err != nil {
		return ContainerStatus{}, err
	}
	if status.ExitCode == nil && out.StatusCode != 0 {
		code := out.StatusCode
		status.ExitCode = &code
	}
	if status.Error == "" && out.Error.Message != "" {
		status.Error = out.Error.Message
	}
	return status, nil
}

func (d *DockerBackend) Inspect(ctx context.Context, containerID string) (ContainerStatus, error) {
	var out dockerInspectResponse
	if err := d.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(containerID)+"/json", nil, &out); err != nil {
		return ContainerStatus{}, err
	}
	return dockerContainerStatus(out), nil
}

func (d *DockerBackend) InternalAddress(ctx context.Context, containerID string) (string, error) {
	var out dockerInspectResponse
	if err := d.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(containerID)+"/json", nil, &out); err != nil {
		return "", err
	}
	for _, network := range out.NetworkSettings.Networks {
		if network.IPAddress != "" {
			return network.IPAddress, nil
		}
	}
	return "", nil
}

// EnsureVolumeSubpaths creates the opaque lineage directory through a short-
// lived helper that alone sees each full backing volume. The 0711 root is
// owner-only writable but traversable by each distinct per-session UID/GID;
// Docker requires a volume subpath to exist before the authority container is
// created.
func (d *DockerBackend) EnsureVolumeSubpaths(ctx context.Context, image, lineageID string, mounts []Mount) error {
	if !validOpaqueLineageID(lineageID) {
		return fmt.Errorf("invalid volume storage lineage")
	}
	initMounts := make([]Mount, 0, len(mounts))
	args := []string{"-d", "-o", "bun", "-g", "bun", "-m", "0711"}
	for index, mount := range mounts {
		if !mount.Volume || mount.Source == "" || mount.VolumeSubpath != lineageID {
			return fmt.Errorf("invalid authority volume subpath request")
		}
		target := fmt.Sprintf("/lineage-volumes/%d", index)
		initMounts = append(initMounts, Mount{Source: mount.Source, Target: target, Volume: true})
		args = append(args, target+"/"+lineageID)
	}
	runID := "authority-volume-init-" + lineageID
	spec := RuntimeSpec{RunID: runID, Image: image, Entrypoint: []string{"install"}, Command: args, User: "0:0", Labels: map[string]string{"gh-agent-broker.run_id": runID, "gh-agent-broker.volume_initializer": "true"}, Mounts: initMounts, Resources: Resources{CPUShares: 2, MemoryMB: 32, PidsLimit: 16}}
	info, err := d.Create(ctx, spec)
	if err != nil {
		return err
	}
	if info.Lifecycle == ContainerNeverStarted {
		if err := d.Start(ctx, info.ID); err != nil {
			return err
		}
	}
	status := info.Status
	if info.Lifecycle != ContainerExited {
		status, err = d.Wait(ctx, info.ID)
		if err != nil {
			return err
		}
	}
	if status.ExitCode == nil || *status.ExitCode != 0 {
		return fmt.Errorf("volume subpath initializer failed")
	}
	return d.Remove(ctx, info.ID)
}

func dockerContainerStatus(out dockerInspectResponse) ContainerStatus {
	status := ContainerStatus{ID: out.ID, Running: out.State.Running, Error: out.State.Error}
	if !out.State.Running {
		exit := out.State.ExitCode
		status.ExitCode = &exit
	}
	status.StartedAt = parseDockerTime(out.State.StartedAt)
	status.EndedAt = parseDockerTime(out.State.FinishedAt)
	return status
}

func (d *DockerBackend) Logs(ctx context.Context, containerID string, limitBytes int) (string, error) {
	path := "/containers/" + url.PathEscape(containerID) + "/logs?stdout=1&stderr=1&tail=200"
	var buf bytes.Buffer
	if err := d.do(ctx, http.MethodGet, path, nil, &buf); err != nil {
		return "", err
	}
	b := stripDockerLogHeaders(buf.Bytes())
	if len(b) > limitBytes {
		b = b[len(b)-limitBytes:]
	}
	return string(b), nil
}

func (d *DockerBackend) Stop(ctx context.Context, containerID string, grace time.Duration) error {
	seconds := int(grace.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return d.do(ctx, http.MethodPost, fmt.Sprintf("/containers/%s/stop?t=%d", url.PathEscape(containerID), seconds), nil, nil)
}

func (d *DockerBackend) Remove(ctx context.Context, containerID string) error {
	return d.do(ctx, http.MethodDelete, "/containers/"+url.PathEscape(containerID)+"?force=1&v=1", nil, nil)
}

func (d *DockerBackend) WriteFile(ctx context.Context, image string, mounts []Mount, targetPath string, contents []byte) error {
	parent := path.Dir(path.Clean(targetPath))
	name := path.Base(path.Clean(targetPath))
	if parent == "." || parent == "/" || name == "." || name == "/" {
		return fmt.Errorf("invalid target path %q", targetPath)
	}
	reqBody := dockerCreateRequest{
		Image: image,
		User:  "0:0",
		Labels: map[string]string{
			"gh-agent-broker.sandbox.status_writer": "true",
		},
		HostConfig: dockerHostConfig{
			ReadonlyRootfs:  false,
			SecurityOpt:     []string{"no-new-privileges"},
			CapDrop:         []string{"ALL"},
			NetworkMode:     "none",
			Binds:           binds(mounts),
			PidsLimit:       64,
			Memory:          64 * 1024 * 1024,
			AutoRemove:      false,
			Privileged:      false,
			PublishAllPorts: false,
		},
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := d.doJSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape("sandbox-status-writer-"+time.Now().UTC().Format("20060102T150405.000000000")), reqBody, &created); err != nil {
		return err
	}
	if created.ID == "" {
		return fmt.Errorf("docker status writer did not return container id")
	}
	defer func() {
		//nolint:errcheck // Best-effort removal of a helper container after writing status.
		_ = d.Remove(context.WithoutCancel(ctx), created.ID)
	}()
	archive, err := singleFileTar(name, contents, 0o644)
	if err != nil {
		return err
	}
	return d.doWithContentType(ctx, http.MethodPut, "/containers/"+url.PathEscape(created.ID)+"/archive?path="+url.QueryEscape(parent), bytes.NewReader(archive), nil, "application/x-tar")
}

func (d *DockerBackend) MakeRemovable(ctx context.Context, image, path string) error {
	cleanPath := filepath.Clean(path)
	reqBody := dockerCreateRequest{
		Image:      image,
		Entrypoint: []string{"sh", "-c"},
		Cmd:        []string{"chmod -R a+rwX /cleanup"},
		User:       "0:0",
		Labels: map[string]string{
			"gh-agent-broker.sandbox.cleanup": "true",
		},
		HostConfig: dockerHostConfig{
			ReadonlyRootfs:  true,
			SecurityOpt:     []string{"no-new-privileges"},
			NetworkMode:     "none",
			Binds:           []string{cleanPath + ":/cleanup:rw"},
			PidsLimit:       64,
			Memory:          64 * 1024 * 1024,
			AutoRemove:      false,
			Privileged:      false,
			PublishAllPorts: false,
		},
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := d.doJSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape("sandbox-cleanup-"+time.Now().UTC().Format("20060102T150405.000000000")), reqBody, &created); err != nil {
		return err
	}
	if created.ID == "" {
		return fmt.Errorf("docker cleanup helper did not return container id")
	}
	defer func() {
		//nolint:errcheck // Best-effort removal of a short-lived cleanup helper after the primary operation result is known.
		_ = d.Remove(context.WithoutCancel(ctx), created.ID)
	}()
	if err := d.Start(ctx, created.ID); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, err := d.Inspect(ctx, created.ID)
		if err != nil {
			return err
		}
		if !status.Running {
			if status.ExitCode == nil || *status.ExitCode != 0 {
				if status.ExitCode == nil {
					return fmt.Errorf("cleanup helper exited without exit code")
				}
				return fmt.Errorf("cleanup helper exited with status %d", *status.ExitCode)
			}
			return nil
		}
		if time.Now().After(deadline) {
			//nolint:errcheck // Best-effort stop before returning the timeout error.
			_ = d.Stop(context.WithoutCancel(ctx), created.ID, time.Second)
			return fmt.Errorf("cleanup helper timed out")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (d *DockerBackend) imageDigest(ctx context.Context, image string) (string, error) {
	var out struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
	}
	if err := d.doJSON(ctx, http.MethodGet, "/images/"+url.PathEscape(image)+"/json", nil, &out); err != nil {
		return "", err
	}
	if len(out.RepoDigests) > 0 {
		return out.RepoDigests[0], nil
	}
	if out.ID != "" {
		return out.ID, nil
	}
	return image, nil
}

func (d *DockerBackend) doJSON(ctx context.Context, method, path string, in, out interface{}) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	var w io.Writer
	if out != nil {
		var buf bytes.Buffer
		w = &buf
		if err := d.do(ctx, method, path, body, w); err != nil {
			return err
		}
		if buf.Len() == 0 {
			return nil
		}
		return json.Unmarshal(buf.Bytes(), out)
	}
	return d.do(ctx, method, path, body, nil)
}

func (d *DockerBackend) do(ctx context.Context, method, path string, body io.Reader, out io.Writer) error {
	return d.doWithContentType(ctx, method, path, body, out, "application/json")
}

func (d *DockerBackend) doWithContentType(ctx context.Context, method, path string, body io.Reader, out io.Writer, contentType string) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer closeBody(resp.Body)
	if resp.StatusCode == http.StatusNotFound && method == http.MethodDelete {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return DockerError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: "read error body: " + readErr.Error()}
		}
		return DockerError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: string(b)}
	}
	if out != nil {
		_, err = io.Copy(out, resp.Body)
		return err
	}
	return nil
}

type DockerError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e DockerError) Error() string {
	return fmt.Sprintf("docker %s %s failed: status %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

func DockerStatusCode(err error) (int, bool) {
	var dockerErr DockerError
	if errors.As(err, &dockerErr) {
		return dockerErr.StatusCode, true
	}
	return 0, false
}

func singleFileTar(name string, contents []byte, mode int64) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: mode,
		Size: int64(len(contents)),
		Uid:  1000,
		Gid:  1000,
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(contents); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type dockerCreateRequest struct {
	Image      string            `json:"Image"`
	Platform   string            `json:"Platform,omitempty"`
	Entrypoint []string          `json:"Entrypoint,omitempty"`
	Cmd        []string          `json:"Cmd,omitempty"`
	User       string            `json:"User"`
	Env        []string          `json:"Env,omitempty"`
	Labels     map[string]string `json:"Labels,omitempty"`
	WorkingDir string            `json:"WorkingDir,omitempty"`
	HostConfig dockerHostConfig  `json:"HostConfig"`
}

type dockerHostConfig struct {
	ReadonlyRootfs  bool          `json:"ReadonlyRootfs"`
	SecurityOpt     []string      `json:"SecurityOpt"`
	CapDrop         []string      `json:"CapDrop"`
	NetworkMode     string        `json:"NetworkMode"`
	Binds           []string      `json:"Binds"`
	Mounts          []dockerMount `json:"Mounts,omitempty"`
	PidsLimit       int64         `json:"PidsLimit,omitempty"`
	Memory          int64         `json:"Memory,omitempty"`
	CPUWeight       int           `json:"CpuShares,omitempty"`
	AutoRemove      bool          `json:"AutoRemove"`
	Privileged      bool          `json:"Privileged"`
	PublishAllPorts bool          `json:"PublishAllPorts"`
}

type dockerMount struct {
	Type          string               `json:"Type"`
	Source        string               `json:"Source"`
	Target        string               `json:"Target"`
	ReadOnly      bool                 `json:"ReadOnly,omitempty"`
	VolumeOptions *dockerVolumeOptions `json:"VolumeOptions,omitempty"`
}

type dockerVolumeOptions struct {
	Subpath string `json:"Subpath,omitempty"`
}

type dockerInspectResponse struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Running    bool   `json:"Running"`
		ExitCode   int    `json:"ExitCode"`
		Error      string `json:"Error"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
	} `json:"State"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func runtimeSpecDigest(spec RuntimeSpec) (string, error) {
	copySpec := spec
	copySpec.Labels = cloneStringMap(spec.Labels)
	delete(copySpec.Labels, "gh-agent-broker.launch_spec")
	b, err := json.Marshal(copySpec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("v1:%x", sum[:]), nil
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for key, value := range in {
		out[key] = value
	}
	return out
}

type dockerWaitResponse struct {
	StatusCode int `json:"StatusCode"`
	Error      struct {
		Message string `json:"Message"`
	} `json:"Error"`
}

func envList(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

func binds(mounts []Mount) []string {
	out := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		if mount.Volume {
			continue
		}
		mode := "rw"
		if mount.ReadOnly {
			mode = "ro"
		}
		out = append(out, filepath.Clean(mount.Source)+":"+mount.Target+":"+mode)
	}
	return out
}

func dockerMounts(mounts []Mount) []dockerMount {
	var out []dockerMount
	for _, mount := range mounts {
		if !mount.Volume {
			continue
		}
		out = append(out, dockerMount{Type: "volume", Source: mount.Source, Target: mount.Target, ReadOnly: mount.ReadOnly, VolumeOptions: &dockerVolumeOptions{Subpath: mount.VolumeSubpath}})
	}
	return out
}

func networkMode(network NetworkPolicy) string {
	if network.None {
		return "none"
	}
	return network.Network
}

func parseDockerTime(s string) time.Time {
	if s == "" || strings.HasPrefix(s, "0001-") {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func stripDockerLogHeaders(b []byte) []byte {
	var out []byte
	for len(b) >= 8 {
		size := int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7])
		if size < 0 || size > len(b)-8 {
			return b
		}
		out = append(out, b[8:8+size]...)
		b = b[8+size:]
	}
	if len(out) == 0 {
		return b
	}
	return out
}

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil {
		return
	}
}
