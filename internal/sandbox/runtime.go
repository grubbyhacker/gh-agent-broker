package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

type RuntimeBackend interface {
	Create(ctx context.Context, spec RuntimeSpec) (ContainerInfo, error)
	Start(ctx context.Context, containerID string) error
	Inspect(ctx context.Context, containerID string) (ContainerStatus, error)
	Logs(ctx context.Context, containerID string, limitBytes int) (string, error)
	Stop(ctx context.Context, containerID string, grace time.Duration) error
	Remove(ctx context.Context, containerID string) error
}

type RuntimeSpec struct {
	RunID      string
	Image      string
	Command    []string
	User       string
	Env        map[string]string
	Labels     map[string]string
	Mounts     []Mount
	Network    NetworkPolicy
	Resources  Resources
	WorkingDir string
	Timeout    time.Duration
}

type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

type ContainerInfo struct {
	ID          string
	ImageDigest string
}

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
	imageDigest, err := d.imageDigest(ctx, spec.Image)
	if err != nil {
		imageDigest = spec.Image
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
		},
	}
	var out struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	path := "/containers/create?name=" + url.QueryEscape("sandbox-"+spec.RunID)
	if err := d.doJSON(ctx, http.MethodPost, path, reqBody, &out); err != nil {
		return ContainerInfo{}, err
	}
	return ContainerInfo{ID: out.ID, ImageDigest: imageDigest}, nil
}

func (d *DockerBackend) Start(ctx context.Context, containerID string) error {
	return d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerID)+"/start", nil, nil)
}

func (d *DockerBackend) Inspect(ctx context.Context, containerID string) (ContainerStatus, error) {
	var out dockerInspectResponse
	if err := d.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(containerID)+"/json", nil, &out); err != nil {
		return ContainerStatus{}, err
	}
	status := ContainerStatus{ID: out.ID, Running: out.State.Running, Error: out.State.Error}
	if !out.State.Running {
		exit := out.State.ExitCode
		status.ExitCode = &exit
	}
	status.StartedAt = parseDockerTime(out.State.StartedAt)
	status.EndedAt = parseDockerTime(out.State.FinishedAt)
	return status, nil
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
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
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
			return fmt.Errorf("docker %s %s failed: status %d: read error body: %w", method, path, resp.StatusCode, readErr)
		}
		return fmt.Errorf("docker %s %s failed: status %d: %s", method, path, resp.StatusCode, string(b))
	}
	if out != nil {
		_, err = io.Copy(out, resp.Body)
		return err
	}
	return nil
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

type dockerHostConfig struct {
	ReadonlyRootfs  bool     `json:"ReadonlyRootfs"`
	SecurityOpt     []string `json:"SecurityOpt"`
	CapDrop         []string `json:"CapDrop"`
	NetworkMode     string   `json:"NetworkMode"`
	Binds           []string `json:"Binds"`
	PidsLimit       int64    `json:"PidsLimit,omitempty"`
	Memory          int64    `json:"Memory,omitempty"`
	CPUWeight       int      `json:"CpuShares,omitempty"`
	AutoRemove      bool     `json:"AutoRemove"`
	Privileged      bool     `json:"Privileged"`
	PublishAllPorts bool     `json:"PublishAllPorts"`
}

type dockerInspectResponse struct {
	ID    string `json:"Id"`
	State struct {
		Running    bool   `json:"Running"`
		ExitCode   int    `json:"ExitCode"`
		Error      string `json:"Error"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
	} `json:"State"`
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
