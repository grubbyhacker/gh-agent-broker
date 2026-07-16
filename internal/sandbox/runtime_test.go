package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestDockerCreatePassesPlatform(t *testing.T) {
	backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/containers/create":
			var body dockerCreateRequest
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Platform != "linux/amd64" {
				t.Fatalf("platform=%q", body.Platform)
			}
			if got, want := body.Entrypoint, []string{"bun", "run", "src/cli.ts", "serve"}; !reflect.DeepEqual(got, want) || len(body.Cmd) != 0 || body.WorkingDir != "" {
				t.Fatalf("entrypoint=%q cmd=%q", got, body.Cmd)
			}
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(`{"Id":"created"}`)), Header: make(http.Header)}, nil
		case "/images/worker:latest/json":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Id":"sha256:image"}`)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("request path=%s", req.URL.Path)
			return nil, fmt.Errorf("unexpected request path")
		}
	})}}
	info, err := backend.Create(context.Background(), RuntimeSpec{RunID: "platform", Image: "worker:latest", Platform: "linux/amd64", Entrypoint: []string{"bun", "run", "src/cli.ts", "serve"}, Labels: map[string]string{}})
	if err != nil || info.ID != "created" {
		t.Fatalf("Create()=%+v err=%v", info, err)
	}
}

func TestDockerCreateSerializesVolumeSubpathsWithoutFullVolumeBinds(t *testing.T) {
	const lineage = "11111111111111111111111111111111"
	backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/containers/create":
			var body dockerCreateRequest
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if got, want := body.HostConfig.Binds, []string{"/host/credential:/run/credential:ro"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("binds=%q, want %q", got, want)
			}
			if len(body.HostConfig.Mounts) != 3 {
				t.Fatalf("volume mounts=%+v", body.HostConfig.Mounts)
			}
			for _, mount := range body.HostConfig.Mounts {
				if mount.Type != "volume" || mount.VolumeOptions == nil || mount.VolumeOptions.Subpath != lineage {
					t.Fatalf("volume mount does not enforce lineage subpath: %+v", mount)
				}
			}
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(`{"Id":"created"}`)), Header: make(http.Header)}, nil
		case "/images/worker:latest/json":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Id":"sha256:image"}`)), Header: make(http.Header)}, nil
		default:
			return nil, fmt.Errorf("unexpected request path %q", req.URL.Path)
		}
	})}}
	mounts := []Mount{
		{Source: "journal", Target: "/var/lib/agentd", Volume: true, VolumeSubpath: lineage},
		{Source: "checkpoints", Target: "/var/lib/agentd/checkpoints", Volume: true, VolumeSubpath: lineage},
		{Source: "evidence", Target: "/var/lib/agentd/evidence", Volume: true, VolumeSubpath: lineage},
		{Source: "/host/credential", Target: "/run/credential", ReadOnly: true},
	}
	if _, err := backend.Create(context.Background(), RuntimeSpec{RunID: "subpaths", Image: "worker:latest", Labels: map[string]string{}, Mounts: mounts}); err != nil {
		t.Fatal(err)
	}
}

func TestDockerAdoptRequiresExactDurableLaunchIdentity(t *testing.T) {
	spec := RuntimeSpec{
		RunID: "run-123",
		Image: "worker:latest",
		Labels: map[string]string{
			"gh-agent-broker.run_id": "run-123",
		},
	}
	digest, err := runtimeSpecDigest(spec)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name       string
		container  string
		runID      string
		specDigest string
		wantError  bool
	}{
		{name: "exact match", container: "/sandbox-run-123", runID: "run-123", specDigest: digest},
		{name: "wrong name", container: "/sandbox-other", runID: "run-123", specDigest: digest, wantError: true},
		{name: "wrong run label", container: "/sandbox-run-123", runID: "run-other", specDigest: digest, wantError: true},
		{name: "wrong spec label", container: "/sandbox-run-123", runID: "run-123", specDigest: "v1:other", wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := `{
				"Id":"container-id",
				"Name":"` + tt.container + `",
				"Image":"sha256:image",
				"Config":{"Labels":{
					"gh-agent-broker.run_id":"` + tt.runID + `",
					"gh-agent-broker.launch_spec":"` + tt.specDigest + `"
				}},
				"State":{"Running":true,"StartedAt":"2026-07-13T00:00:00Z"}
			}`
			backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet || req.URL.Path != "/containers/sandbox-run-123/json" {
					t.Fatalf("request=%s %s", req.Method, req.URL.Path)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(body)),
					Header:     make(http.Header),
				}, nil
			})}}

			info, err := backend.adopt(context.Background(), spec)
			if tt.wantError {
				if err == nil {
					t.Fatalf("adopted mismatched container: %+v", info)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !info.Existing || info.Lifecycle != ContainerRunning || info.ID != "container-id" {
				t.Fatalf("adopted container=%+v", info)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
