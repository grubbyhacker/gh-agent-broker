package sandbox

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDockerCreateAppliesTmpfsStorageAndPrivateNetworkContract(t *testing.T) {
	var create dockerCreateRequest
	backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/images/"):
			return jsonResponse(`{"Id":"sha256:image","RepoDigests":["worker@sha256:digest"],"Architecture":"amd64","Os":"linux"}`), nil
		case req.Method == http.MethodPost && req.URL.Path == "/containers/create":
			if err := json.NewDecoder(req.Body).Decode(&create); err != nil {
				t.Fatal(err)
			}
			return jsonResponse(`{"Id":"container-id"}`), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL)
			return nil, errors.New("unexpected request")
		}
	})}}
	info, err := backend.Create(context.Background(), RuntimeSpec{
		RunID: "run-exec", Image: "worker@sha256:digest", User: "1000:1000",
		Network: NetworkPolicy{
			Network: "codex-execution-internal", PrivateBroker: true,
			CodexRelay: true,
		},
		Tmpfs: map[string]int64{"/dev/shm": 64}, StorageLimitMB: 8192,
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.ImageDigest != "worker@sha256:digest" || info.Platform != "linux/amd64" {
		t.Fatalf("image identity=%+v", info)
	}
	if create.HostConfig.NetworkMode != "codex-execution-internal" ||
		create.HostConfig.Tmpfs["/dev/shm"] != "rw,noexec,nosuid,nodev,size=64m,mode=0700" ||
		create.HostConfig.StorageOpt["size"] != "8192M" ||
		create.HostConfig.Privileged || create.HostConfig.PublishAllPorts {
		t.Fatalf("host config=%+v", create.HostConfig)
	}
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(body)),
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

func TestDockerInjectSecretStreamsMode0600ArchiveOnlyAfterContainerStart(t *testing.T) {
	t.Parallel()
	var archiveName string
	var archiveMode int64
	var archiveBody string
	backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/containers/container-id/json":
			return jsonResponse(`{"Id":"container-id","State":{"Running":true,"StartedAt":"2026-07-30T12:00:00Z"}}`), nil
		case req.Method == http.MethodPut && req.URL.Path == "/containers/container-id/archive":
			if req.URL.Query().Get("path") != codexInjectionDir || req.Header.Get("Content-Type") != "application/x-tar" {
				t.Fatalf("archive request=%s headers=%v", req.URL, req.Header)
			}
			reader := tar.NewReader(req.Body)
			header, err := reader.Next()
			if err != nil {
				t.Fatal(err)
			}
			archiveName, archiveMode = header.Name, header.Mode
			body, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			archiveBody = string(body)
			return jsonResponse(""), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL)
			return nil, errors.New("unexpected request")
		}
	})}}
	bundle := `{"tokens":{"access_token":"access-only","refresh_token":""}}`
	if err := backend.InjectSecret(context.Background(), "container-id", codexInjectionDir, codexInjectionName, []byte(bundle)); err != nil {
		t.Fatal(err)
	}
	if archiveName != codexInjectionName || archiveMode != 0o600 || archiveBody != bundle {
		t.Fatalf("archive name=%q mode=%o body=%q", archiveName, archiveMode, archiveBody)
	}

	backend.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(`{"Id":"container-id","State":{"Running":false}}`), nil
	})}
	if err := backend.InjectSecret(context.Background(), "container-id", codexInjectionDir, codexInjectionName, []byte(bundle)); err == nil {
		t.Fatal("injected into a container that was not running")
	}
	if err := backend.InjectSecret(context.Background(), "container-id", "/work", codexInjectionName, []byte(bundle)); err == nil {
		t.Fatal("accepted a non-tmpfs injection target")
	}
}

func TestDockerWaitForPathUsesBoundedInContainerArchiveProbe(t *testing.T) {
	t.Parallel()
	var probes int
	backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		probes++
		if req.Method != http.MethodHead || req.URL.Query().Get("path") != codexAcceptanceMarker {
			t.Fatalf("probe=%s %s", req.Method, req.URL)
		}
		status := http.StatusNotFound
		if probes == 2 {
			status = http.StatusOK
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: http.NoBody}, nil
	})}}
	if err := backend.WaitForPath(context.Background(), "container-id", codexAcceptanceMarker, time.Second); err != nil {
		t.Fatal(err)
	}
	if probes != 2 {
		t.Fatalf("probes=%d", probes)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
