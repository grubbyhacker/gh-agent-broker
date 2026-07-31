package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
		create.HostConfig.Tmpfs["/dev/shm"] != "rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=1000,gid=1000" ||
		create.HostConfig.StorageOpt["size"] != "8192M" ||
		create.HostConfig.Privileged || create.HostConfig.PublishAllPorts {
		t.Fatalf("host config=%+v", create.HostConfig)
	}
}

func TestTmpfsOptionsRequireExplicitNumericOwnership(t *testing.T) {
	t.Parallel()
	entries := map[string]int64{"/dev/shm": 64}
	for _, user := range []string{"", "1000", "worker:worker", "1000:worker"} {
		if _, err := tmpfsOptions(entries, user); err == nil {
			t.Fatalf("accepted tmpfs with non-numeric container user %q", user)
		}
	}
	options, err := tmpfsOptions(entries, "10000:10001")
	if err != nil {
		t.Fatal(err)
	}
	if options["/dev/shm"] != "rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=10000,gid=10001" {
		t.Fatalf("tmpfs options=%q", options["/dev/shm"])
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

func TestDockerInjectSecretStreamsOnlyOnExecStdinAfterContainerStart(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	payload := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		//nolint:errcheck // The pipe is test-only and its payload is asserted below.
		defer serverConn.Close()
		req, readErr := http.ReadRequest(bufio.NewReader(serverConn))
		if readErr != nil {
			serverErr <- readErr
			return
		}
		if req.Method != http.MethodPost || req.URL.Path != "/exec/exec-id/start" {
			serverErr <- errors.New("unexpected exec start request")
			return
		}
		if _, readErr = io.ReadAll(req.Body); readErr != nil {
			serverErr <- readErr
			return
		}
		if _, writeErr := io.WriteString(serverConn, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"); writeErr != nil {
			serverErr <- writeErr
			return
		}
		body, readErr := io.ReadAll(serverConn)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		payload <- body
		serverErr <- nil
	}()

	var create dockerExecCreateRequest
	backend := &DockerBackend{
		dialContext: func(context.Context, string, string) (net.Conn, error) { return clientConn, nil },
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case req.Method == http.MethodGet && req.URL.Path == "/containers/container-id/json":
				return jsonResponse(`{"Id":"container-id","State":{"Running":true,"StartedAt":"2026-07-30T12:00:00Z"}}`), nil
			case req.Method == http.MethodPost && req.URL.Path == "/containers/container-id/exec":
				if err := json.NewDecoder(req.Body).Decode(&create); err != nil {
					t.Fatal(err)
				}
				return jsonResponse(`{"Id":"exec-id"}`), nil
			case req.Method == http.MethodGet && req.URL.Path == "/exec/exec-id/json":
				return jsonResponse(`{"Running":false,"ExitCode":0}`), nil
			default:
				t.Fatalf("unexpected request %s %s", req.Method, req.URL)
				return nil, errors.New("unexpected request")
			}
		})},
	}
	bundle := `{"tokens":{"access_token":"access-only","refresh_token":""}}`
	if err := backend.InjectSecret(context.Background(), "container-id", codexInjectionDir, codexInjectionName, []byte(bundle)); err != nil {
		t.Fatal(err)
	}
	if !create.AttachStdin || create.AttachStdout || create.AttachStderr || strings.Contains(strings.Join(create.Cmd, " "), "access-only") {
		t.Fatalf("unsafe secret injection exec=%+v", create)
	}
	if got := string(<-payload); got != bundle {
		t.Fatalf("exec stdin=%q, want access-only bundle", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
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

func TestDockerWaitForPathUsesBoundedInContainerExecProbe(t *testing.T) {
	t.Parallel()
	var probes int
	backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/containers/container-id/exec":
			probes++
			var create dockerExecCreateRequest
			if err := json.NewDecoder(req.Body).Decode(&create); err != nil {
				t.Fatal(err)
			}
			if strings.Join(create.Cmd, " ") != "test -e "+codexAcceptanceMarker {
				t.Fatalf("path probe command=%v", create.Cmd)
			}
			return jsonResponse(`{"Id":"exec-id"}`), nil
		case req.Method == http.MethodPost && req.URL.Path == "/exec/exec-id/start":
			return jsonResponse(""), nil
		case req.Method == http.MethodGet && req.URL.Path == "/exec/exec-id/json":
			exitCode := 1
			if probes == 2 {
				exitCode = 0
			}
			return jsonResponse(fmt.Sprintf(`{"Running":false,"ExitCode":%d}`, exitCode)), nil
		default:
			t.Fatalf("unexpected path probe request=%s %s", req.Method, req.URL)
			return nil, errors.New("unexpected request")
		}
	})}}
	if err := backend.WaitForPath(context.Background(), "container-id", codexAcceptanceMarker, time.Second); err != nil {
		t.Fatal(err)
	}
	if probes != 2 {
		t.Fatalf("probes=%d", probes)
	}
}

func TestDockerPathExistsDistinguishesMissingAcceptanceMarker(t *testing.T) {
	t.Parallel()
	exitCode := 1
	backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/containers/container-id/exec":
			return jsonResponse(`{"Id":"exec-id"}`), nil
		case req.Method == http.MethodPost && req.URL.Path == "/exec/exec-id/start":
			return jsonResponse(""), nil
		case req.Method == http.MethodGet && req.URL.Path == "/exec/exec-id/json":
			return jsonResponse(fmt.Sprintf(`{"Running":false,"ExitCode":%d}`, exitCode)), nil
		default:
			t.Fatalf("unexpected path probe request=%s %s", req.Method, req.URL)
			return nil, errors.New("unexpected request")
		}
	})}}
	exists, err := backend.PathExists(context.Background(), "container-id", codexAcceptanceMarker)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("missing marker reported as present")
	}
	exitCode = 0
	exists, err = backend.PathExists(context.Background(), "container-id", codexAcceptanceMarker)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("acceptance marker reported as missing")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
