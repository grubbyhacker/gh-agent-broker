package sandbox

import (
	"archive/tar"
	"bufio"
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
	InjectSecret(ctx context.Context, containerID, targetDir, name string, contents []byte) error
	PathExists(ctx context.Context, containerID, targetPath string) (bool, error)
	WaitForPath(ctx context.Context, containerID, targetPath string, timeout time.Duration) error
	Wait(ctx context.Context, containerID string) (ContainerStatus, error)
	Inspect(ctx context.Context, containerID string) (ContainerStatus, error)
	Logs(ctx context.Context, containerID string, limitBytes int) (string, error)
	Stop(ctx context.Context, containerID string, grace time.Duration) error
	Remove(ctx context.Context, containerID string) error
}

type RuntimeSpec struct {
	RunID          string
	Image          string
	Command        []string
	User           string
	Env            map[string]string
	Labels         map[string]string
	Mounts         []Mount
	Network        NetworkPolicy
	Resources      Resources
	WorkingDir     string
	Timeout        time.Duration
	Tmpfs          map[string]int64
	StorageLimitMB int64
}

type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

type ContainerInfo struct {
	ID          string
	ImageDigest string
	Platform    string
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
	socket      string
	client      *http.Client
	dialContext func(context.Context, string, string) (net.Conn, error)
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
	return &DockerBackend{
		socket: socket, client: &http.Client{Transport: transport, Timeout: 30 * time.Second},
		dialContext: (&net.Dialer{}).DialContext,
	}
}

func (d *DockerBackend) Create(ctx context.Context, spec RuntimeSpec) (ContainerInfo, error) {
	spec.Labels = cloneStringMap(spec.Labels)
	specDigest, err := runtimeSpecDigest(spec)
	if err != nil {
		return ContainerInfo{}, fmt.Errorf("fingerprint sandbox runtime spec: %w", err)
	}
	spec.Labels["gh-agent-broker.launch_spec"] = specDigest
	imageDigest, platform, err := d.imageIdentity(ctx, spec.Image)
	if err != nil {
		imageDigest = spec.Image
	}
	tmpfs, err := tmpfsOptions(spec.Tmpfs, spec.User)
	if err != nil {
		return ContainerInfo{}, err
	}
	reqBody := dockerCreateRequest{
		Image:      spec.Image,
		Cmd:        spec.Command,
		User:       spec.User,
		Env:        envList(spec.Env),
		Labels:     spec.Labels,
		WorkingDir: spec.WorkingDir,
		HostConfig: dockerHostConfig{
			ReadonlyRootfs:  false,
			SecurityOpt:     []string{"no-new-privileges"},
			CapDrop:         []string{"ALL"},
			NetworkMode:     networkMode(spec.Network),
			Binds:           binds(spec.Mounts),
			PidsLimit:       spec.Resources.PidsLimit,
			Memory:          spec.Resources.MemoryMB * 1024 * 1024,
			CPUWeight:       spec.Resources.CPUShares,
			AutoRemove:      false,
			Privileged:      false,
			PublishAllPorts: false,
			Tmpfs:           tmpfs,
			StorageOpt:      storageOptions(spec.StorageLimitMB),
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
	return ContainerInfo{ID: out.ID, ImageDigest: imageDigest, Platform: platform, Lifecycle: ContainerNeverStarted}, nil
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
	return ContainerInfo{ID: out.ID, ImageDigest: out.Image, Platform: out.Platform, Existing: true, Lifecycle: lifecycle, Status: status}, nil
}

func (d *DockerBackend) Start(ctx context.Context, containerID string) error {
	return d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerID)+"/start", nil, nil)
}

func (d *DockerBackend) InjectSecret(
	ctx context.Context,
	containerID, targetDir, name string,
	contents []byte,
) error {
	cleanDir := path.Clean(targetDir)
	if cleanDir != "/dev/shm" && !strings.HasPrefix(cleanDir, "/dev/shm/") {
		return fmt.Errorf("secret injection target must be within /dev/shm")
	}
	if path.Base(name) != name || name == "." || name == "/" {
		return fmt.Errorf("invalid secret injection name")
	}
	if len(contents) == 0 || len(contents) > 64*1024 {
		return fmt.Errorf("secret injection payload must be between 1 and 65536 bytes")
	}
	status, err := d.Inspect(ctx, containerID)
	if err != nil {
		return fmt.Errorf("inspect secret injection target: %w", err)
	}
	if !status.Running || status.StartedAt.IsZero() {
		return fmt.Errorf("secret injection target is not running")
	}

	execID, err := d.createExec(ctx, containerID, dockerExecCreateRequest{
		AttachStdin: true,
		Cmd: []string{
			"sh", "-c",
			`set -eu; umask 077; mkdir -p "$1"; chmod 0700 "$1"; cat > "$1/$2"; chmod 0600 "$1/$2"`,
			"codex-secret-injector", cleanDir, name,
		},
	})
	if err != nil {
		return fmt.Errorf("create secret injection exec: %w", err)
	}
	if err := d.startExecWithInput(ctx, execID, contents); err != nil {
		return fmt.Errorf("stream secret injection stdin: %w", err)
	}
	exitCode, err := d.waitExec(ctx, execID, 10*time.Second)
	if err != nil {
		return fmt.Errorf("wait for secret injection exec: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("secret injection exec exited with status %d", exitCode)
	}
	return nil
}

func (d *DockerBackend) WaitForPath(
	ctx context.Context,
	containerID, targetPath string,
	timeout time.Duration,
) error {
	if timeout <= 0 || timeout > time.Minute {
		return fmt.Errorf("wait timeout must be positive and at most one minute")
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		exists, err := d.PathExists(waitCtx, containerID, targetPath)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("wait for in-container acceptance marker: %w", waitCtx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (d *DockerBackend) PathExists(
	ctx context.Context,
	containerID, targetPath string,
) (bool, error) {
	cleanPath := path.Clean(targetPath)
	if cleanPath != "/dev/shm" && !strings.HasPrefix(cleanPath, "/dev/shm/") {
		return false, fmt.Errorf("path target must be within /dev/shm")
	}
	execID, err := d.createExec(ctx, containerID, dockerExecCreateRequest{
		Cmd: []string{"test", "-e", cleanPath},
	})
	if err != nil {
		return false, fmt.Errorf("create in-container path probe: %w", err)
	}
	if err := d.startExec(ctx, execID); err != nil {
		return false, fmt.Errorf("start in-container path probe: %w", err)
	}
	exitCode, err := d.waitExec(ctx, execID, 10*time.Second)
	if err != nil {
		return false, fmt.Errorf("wait for in-container path probe: %w", err)
	}
	switch exitCode {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, fmt.Errorf("in-container path probe exited with status %d", exitCode)
	}
}

func (d *DockerBackend) createExec(
	ctx context.Context,
	containerID string,
	req dockerExecCreateRequest,
) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	if err := d.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerID)+"/exec", req, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("docker exec create returned no id")
	}
	return out.ID, nil
}

func (d *DockerBackend) startExec(ctx context.Context, execID string) error {
	return d.doJSON(ctx, http.MethodPost, "/exec/"+url.PathEscape(execID)+"/start", dockerExecStartRequest{}, nil)
}

func (d *DockerBackend) startExecWithInput(ctx context.Context, execID string, contents []byte) error {
	dialContext := d.dialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{}).DialContext
	}
	conn, err := dialContext(ctx, "unix", d.socket)
	if err != nil {
		return err
	}
	//nolint:errcheck // The exec result is verified separately after stdin has been sent.
	defer conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	body, err := json.Marshal(dockerExecStartRequest{})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://docker/exec/"+url.PathEscape(execID)+"/start",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	if err := req.Write(conn); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer closeBody(resp.Body)
		responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return readErr
		}
		return DockerError{
			Method: http.MethodPost, Path: req.URL.Path,
			StatusCode: resp.StatusCode, Body: string(responseBody),
		}
	}
	if _, err := conn.Write(contents); err != nil {
		return err
	}
	return nil
}

func (d *DockerBackend) waitExec(ctx context.Context, execID string, timeout time.Duration) (int, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		var inspect dockerExecInspectResponse
		if err := d.doJSON(waitCtx, http.MethodGet, "/exec/"+url.PathEscape(execID)+"/json", nil, &inspect); err != nil {
			return 0, err
		}
		if !inspect.Running {
			return inspect.ExitCode, nil
		}
		select {
		case <-waitCtx.Done():
			return 0, waitCtx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
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

func (d *DockerBackend) imageIdentity(ctx context.Context, image string) (string, string, error) {
	var out struct {
		ID           string   `json:"Id"`
		RepoDigests  []string `json:"RepoDigests"`
		Architecture string   `json:"Architecture"`
		OS           string   `json:"Os"`
	}
	if err := d.doJSON(ctx, http.MethodGet, "/images/"+url.PathEscape(image)+"/json", nil, &out); err != nil {
		return "", "", err
	}
	platform := strings.Trim(strings.TrimSpace(out.OS)+"/"+strings.TrimSpace(out.Architecture), "/")
	if len(out.RepoDigests) > 0 {
		return out.RepoDigests[0], platform, nil
	}
	if out.ID != "" {
		return out.ID, platform, nil
	}
	return image, platform, nil
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
	Entrypoint []string          `json:"Entrypoint,omitempty"`
	Cmd        []string          `json:"Cmd,omitempty"`
	User       string            `json:"User"`
	Env        []string          `json:"Env,omitempty"`
	Labels     map[string]string `json:"Labels,omitempty"`
	WorkingDir string            `json:"WorkingDir,omitempty"`
	HostConfig dockerHostConfig  `json:"HostConfig"`
}

type dockerExecCreateRequest struct {
	AttachStdin  bool     `json:"AttachStdin"`
	AttachStdout bool     `json:"AttachStdout"`
	AttachStderr bool     `json:"AttachStderr"`
	Cmd          []string `json:"Cmd"`
}

type dockerExecStartRequest struct {
	Detach bool `json:"Detach"`
	Tty    bool `json:"Tty"`
}

type dockerExecInspectResponse struct {
	Running  bool `json:"Running"`
	ExitCode int  `json:"ExitCode"`
}

type dockerHostConfig struct {
	ReadonlyRootfs  bool              `json:"ReadonlyRootfs"`
	SecurityOpt     []string          `json:"SecurityOpt"`
	CapDrop         []string          `json:"CapDrop"`
	NetworkMode     string            `json:"NetworkMode"`
	Binds           []string          `json:"Binds"`
	PidsLimit       int64             `json:"PidsLimit,omitempty"`
	Memory          int64             `json:"Memory,omitempty"`
	CPUWeight       int               `json:"CpuShares,omitempty"`
	AutoRemove      bool              `json:"AutoRemove"`
	Privileged      bool              `json:"Privileged"`
	PublishAllPorts bool              `json:"PublishAllPorts"`
	Tmpfs           map[string]string `json:"Tmpfs,omitempty"`
	StorageOpt      map[string]string `json:"StorageOpt,omitempty"`
}

type dockerInspectResponse struct {
	ID       string `json:"Id"`
	Name     string `json:"Name"`
	Image    string `json:"Image"`
	Platform string `json:"Platform"`
	Config   struct {
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
		mode := "rw"
		if mount.ReadOnly {
			mode = "ro"
		}
		out = append(out, filepath.Clean(mount.Source)+":"+mount.Target+":"+mode)
	}
	return out
}

func tmpfsOptions(entries map[string]int64, user string) (map[string]string, error) {
	if len(entries) == 0 {
		return map[string]string{}, nil
	}
	uid, gid, ok := strings.Cut(user, ":")
	if !ok || uid == "" || gid == "" {
		return nil, fmt.Errorf("tmpfs requires an explicit numeric uid:gid container user")
	}
	for _, value := range []string{uid, gid} {
		for _, char := range value {
			if char < '0' || char > '9' {
				return nil, fmt.Errorf("tmpfs requires an explicit numeric uid:gid container user")
			}
		}
	}
	out := make(map[string]string, len(entries))
	for target, sizeMB := range entries {
		out[target] = fmt.Sprintf(
			"rw,noexec,nosuid,nodev,size=%dm,mode=0700,uid=%s,gid=%s",
			sizeMB,
			uid,
			gid,
		)
	}
	return out, nil
}

func storageOptions(sizeMB int64) map[string]string {
	if sizeMB < 1 {
		return nil
	}
	return map[string]string{"size": fmt.Sprintf("%dM", sizeMB)}
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
