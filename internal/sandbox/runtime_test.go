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
			if got, want := body.HostConfig.SecurityOpt, []string{"no-new-privileges"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("ordinary runtime SecurityOpt=%q, want %q", got, want)
			}
			if len(body.HostConfig.CapAdd) != 0 {
				t.Fatalf("ordinary runtime must not gain capabilities: %q", body.HostConfig.CapAdd)
			}
			if got, want := body.HostConfig.CapDrop, []string{"ALL"}; !reflect.DeepEqual(got, want) || body.User != "bun" || body.HostConfig.Privileged {
				t.Fatalf("ordinary bun confinement user=%q privileged=%t CapDrop=%q", body.User, body.HostConfig.Privileged, got)
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
	info, err := backend.Create(context.Background(), RuntimeSpec{RunID: "platform", Image: "worker:latest", Platform: "linux/amd64", Entrypoint: []string{"bun", "run", "src/cli.ts", "serve"}, User: "bun", Labels: map[string]string{}})
	if err != nil || info.ID != "created" {
		t.Fatalf("Create()=%+v err=%v", info, err)
	}
}

func TestDockerCreateAgentdSetuidLaunchOmitsOnlyNoNewPrivileges(t *testing.T) {
	cfg := authorityTestConfig(t)
	profile := cfg.AuthorityProfiles["writer"]
	profile.Image = "worker:latest"
	worker := AuthorityWorker{
		WorkerID:               "setuid-launch",
		Profile:                "writer",
		ProfileVersion:         "version",
		PolicyDigest:           "policy",
		WorkerStorageLineageID: "11111111111111111111111111111111",
		WorkerFenceEpoch:       1,
	}
	credential := Mount{Source: "agentd-staging-auth", Target: authorityCodexHomeMountPath, ReadOnly: true, Volume: true}
	spec := authorityWorkerRuntimeSpec(authoritySpec(worker, profile, cfg), "secret", "coordinator-secret", []Mount{credential})
	backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/containers/create":
			var body dockerCreateRequest
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.HostConfig.SecurityOpt) != 0 {
				t.Fatalf("agentd setuid launch SecurityOpt=%q, want no no-new-privileges option", body.HostConfig.SecurityOpt)
			}
			if body.User != "bun" {
				t.Fatalf("agentd server user=%q, want bun", body.User)
			}
			if body.HostConfig.Privileged {
				t.Fatal("agentd authority container must remain non-privileged")
			}
			if got, want := body.HostConfig.CapDrop, []string{"ALL"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("agentd authority CapDrop=%q, want %q", got, want)
			}
			if got, want := body.HostConfig.CapAdd, []string{"SETUID", "SETGID"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("agentd authority CapAdd=%q, want %q", got, want)
			}
			if body.HostConfig.ReadonlyRootfs {
				t.Fatal("agentd authority readonly-rootfs constraint changed")
			}
			if len(body.HostConfig.Binds) != 0 || len(body.HostConfig.Mounts) != 1 {
				t.Fatalf("agentd credential must serialize only as a volume mount: binds=%q mounts=%+v", body.HostConfig.Binds, body.HostConfig.Mounts)
			}
			mount := body.HostConfig.Mounts[0]
			if mount.Type != "volume" || mount.Source != "agentd-staging-auth" || mount.Target != authorityCodexHomeMountPath || !mount.ReadOnly || mount.VolumeOptions == nil || mount.VolumeOptions.Subpath != "" {
				t.Fatalf("agentd credential volume mount=%+v", mount)
			}
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(`{"Id":"created"}`)), Header: make(http.Header)}, nil
		case "/images/worker:latest/json":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Id":"sha256:image"}`)), Header: make(http.Header)}, nil
		default:
			return nil, fmt.Errorf("unexpected request path %q", req.URL.Path)
		}
	})}}
	if _, err := backend.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
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

func TestDockerEnsureVolumeSubpathsUsesTraversableRootAndReusesPrivateStateForReplacement(t *testing.T) {
	const lineage = "11111111111111111111111111111111"
	var rootInitializers, stateInitializers int
	backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/images/worker:latest/json":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Id":"sha256:image"}`)), Header: make(http.Header)}, nil
		case req.Method == http.MethodPost && req.URL.Path == "/containers/create":
			var body dockerCreateRequest
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if got, want := body.HostConfig.SecurityOpt, []string{"no-new-privileges"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("initializer SecurityOpt=%q, want %q", got, want)
			}
			if got, want := body.HostConfig.CapDrop, []string{"ALL"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("initializer CapDrop=%q, want %q", got, want)
			}
			if body.HostConfig.Privileged || body.HostConfig.NetworkMode != "none" || len(body.HostConfig.Binds) != 0 {
				t.Fatalf("initializer confinement privileged=%t network=%q binds=%q", body.HostConfig.Privileged, body.HostConfig.NetworkMode, body.HostConfig.Binds)
			}
			if got, want := body.Entrypoint, []string{"install"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("initializer entrypoint=%q, want %q", got, want)
			}
			switch body.Labels["gh-agent-broker.run_id"] {
			case "authority-volume-init-" + lineage:
				rootInitializers++
				if body.User != "0:0" {
					t.Fatalf("root initializer user=%q, want 0:0", body.User)
				}
				if got, want := body.HostConfig.CapAdd, []string{"CHOWN", "FOWNER"}; !reflect.DeepEqual(got, want) {
					t.Fatalf("root initializer CapAdd=%q, want %q", got, want)
				}
				if got, want := body.Cmd, []string{"-d", "-o", "bun", "-g", "bun", "-m", "0711", "/lineage-volumes/0/" + lineage}; !reflect.DeepEqual(got, want) {
					t.Fatalf("lineage initializer args=%q, want %q", got, want)
				}
				return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(`{"Id":"lineage-initializer"}`)), Header: make(http.Header)}, nil
			case "authority-state-init-" + lineage:
				stateInitializers++
				if body.User != "bun" || len(body.HostConfig.CapAdd) != 0 {
					t.Fatalf("state initializer user=%q CapAdd=%q, want bun with no capabilities", body.User, body.HostConfig.CapAdd)
				}
				if got, want := body.Cmd, []string{"-d", "-o", "bun", "-g", "bun", "-m", "0700", "/lineage-volume/" + lineage + "/.agentd-state"}; !reflect.DeepEqual(got, want) {
					t.Fatalf("state initializer args=%q, want %q", got, want)
				}
				if len(body.HostConfig.Mounts) != 1 || body.HostConfig.Mounts[0].Source != "workspace" || body.HostConfig.Mounts[0].Target != "/lineage-volume" || body.HostConfig.Mounts[0].VolumeOptions == nil || body.HostConfig.Mounts[0].VolumeOptions.Subpath != "" {
					t.Fatalf("private state initializer mount=%+v", body.HostConfig.Mounts)
				}
				return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(`{"Id":"state-initializer"}`)), Header: make(http.Header)}, nil
			default:
				return nil, fmt.Errorf("unexpected initializer labels %+v", body.Labels)
			}
		case req.Method == http.MethodPost && (req.URL.Path == "/containers/lineage-initializer/start" || req.URL.Path == "/containers/state-initializer/start"):
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		case req.Method == http.MethodPost && (req.URL.Path == "/containers/lineage-initializer/wait" || req.URL.Path == "/containers/state-initializer/wait"):
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"StatusCode":0}`)), Header: make(http.Header)}, nil
		case req.Method == http.MethodGet && (req.URL.Path == "/containers/lineage-initializer/json" || req.URL.Path == "/containers/state-initializer/json"):
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"State":{"ExitCode":0}}`)), Header: make(http.Header)}, nil
		case req.Method == http.MethodDelete && (req.URL.Path == "/containers/lineage-initializer" || req.URL.Path == "/containers/state-initializer"):
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		default:
			return nil, fmt.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
		}
	})}}

	mounts := []Mount{{Source: "workspace", Target: agentdControlV1WorkspaceRoot, Volume: true, VolumeSubpath: lineage}}
	for generation := 1; generation <= 2; generation++ {
		if err := backend.ensureAuthorityVolumeSubpaths(context.Background(), "worker:latest", lineage, mounts, agentdControlV1WorkspaceRoot); err != nil {
			t.Fatalf("generation %d initializer: %v", generation, err)
		}
	}
	if rootInitializers != 2 || stateInitializers != 2 {
		t.Fatalf("initializer calls roots=%d states=%d, want two of each for lineage reuse", rootInitializers, stateInitializers)
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

func TestDockerCreateAdoptsLegacyOrdinaryCreatePendingIntentAfterConflict(t *testing.T) {
	spec := RuntimeSpec{
		RunID:   "legacy-pending",
		Image:   "worker:latest",
		Command: []string{"work"},
		User:    "bun",
		Env:     map[string]string{"BROKER_URL": "http://broker"},
		Labels: map[string]string{
			"gh-agent-broker.run_id": "legacy-pending",
		},
		Mounts: []Mount{{Source: "/runs/legacy-pending/work", Target: "/work"}},
	}
	// This label was emitted for the same ordinary-worker spec before
	// RuntimeSpec and Mount gained authority-only fields.
	const legacyDigest = "v1:39b7b62f5e8f5cbbe169dde305575e37960d269079ec681d9e4ca6801fb82e41"
	if currentDigest, err := runtimeSpecDigest(spec); err != nil || currentDigest != legacyDigest {
		t.Fatalf("ordinary spec digest=%q err=%v, want legacy digest %q", currentDigest, err, legacyDigest)
	}

	backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/images/worker:latest/json":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Id":"sha256:image"}`)), Header: make(http.Header)}, nil
		case "/containers/create":
			if req.Method != http.MethodPost || req.URL.Query().Get("name") != "sandbox-legacy-pending" {
				t.Fatalf("create request=%s %s", req.Method, req.URL.String())
			}
			return &http.Response{StatusCode: http.StatusConflict, Body: io.NopCloser(strings.NewReader(`already exists`)), Header: make(http.Header)}, nil
		case "/containers/sandbox-legacy-pending/json":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Id":"container-id","Name":"/sandbox-legacy-pending","Image":"sha256:image","Config":{"Labels":{"gh-agent-broker.run_id":"legacy-pending","gh-agent-broker.launch_spec":"` + legacyDigest + `"}},"State":{}}`)), Header: make(http.Header)}, nil
		default:
			return nil, fmt.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
		}
	})}}

	info, err := backend.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("create_pending collision adoption failed: %v", err)
	}
	if !info.Existing || info.ID != "container-id" || info.Lifecycle != ContainerNeverStarted {
		t.Fatalf("adopted container=%+v", info)
	}
}

func TestRuntimeSpecDigestUsesEffectiveInitializerSecurityClass(t *testing.T) {
	initializer := RuntimeSpec{
		RunID:                      "authority-volume-init-lineage",
		Image:                      "worker:latest",
		Entrypoint:                 []string{"install"},
		Command:                    []string{"-d", "-o", "bun", "-g", "bun", "-m", "0711", "/lineage/lineage"},
		User:                       "0:0",
		Labels:                     map[string]string{"gh-agent-broker.run_id": "authority-volume-init-lineage"},
		Mounts:                     []Mount{{Source: "workspace", Target: "/lineage", Volume: true}},
		Network:                    NetworkPolicy{None: true},
		authorityVolumeInitializer: true,
	}
	initializerDigest, err := runtimeSpecDigest(initializer)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(initializerDigest, "v2:") {
		t.Fatalf("initializer digest=%q, want effective v2 fingerprint", initializerDigest)
	}

	withoutInitializerPrivilege := initializer
	withoutInitializerPrivilege.authorityVolumeInitializer = false
	zeroCapabilityDigest, err := runtimeSpecDigest(withoutInitializerPrivilege)
	if err != nil {
		t.Fatal(err)
	}
	if initializerDigest == zeroCapabilityDigest {
		t.Fatal("initializer privilege class did not change launch fingerprint")
	}

	chownOnly := effectiveRuntimeLaunchFingerprint{CreateRequest: dockerCreateRequestFor(initializer)}
	chownOnly.CreateRequest.HostConfig.CapAdd = []string{"CHOWN"}
	chownOnlyDigest, err := effectiveRuntimeLaunchFingerprintDigest(chownOnly)
	if err != nil {
		t.Fatal(err)
	}
	if initializerDigest == chownOnlyDigest || zeroCapabilityDigest == chownOnlyDigest {
		t.Fatalf("capability fingerprints overlap: initializer=%q zero=%q chown-only=%q", initializerDigest, zeroCapabilityDigest, chownOnlyDigest)
	}
}

func TestRuntimeSpecDigestDistinguishesAuthoritySetuidSecurityClass(t *testing.T) {
	base := RuntimeSpec{
		RunID:      "authority-worker",
		Image:      "worker:latest",
		Entrypoint: []string{"agentd"},
		User:       "bun",
		Labels:     map[string]string{"gh-agent-broker.run_id": "authority-worker"},
		Mounts:     []Mount{{Source: "workspace", Target: "/work", Volume: true, VolumeSubpath: "lineage"}},
	}
	setuid := base
	setuid.AllowAgentdSetuidLauncherPrivilegeTransition = true
	setuidDigest, err := runtimeSpecDigest(setuid)
	if err != nil {
		t.Fatal(err)
	}
	ordinaryDigest, err := runtimeSpecDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	if setuidDigest == ordinaryDigest {
		t.Fatal("authority SETUID/SETGID class did not change launch fingerprint")
	}
	if got, want := dockerCreateRequestFor(setuid).HostConfig.CapAdd, []string{"SETUID", "SETGID"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("authority capabilities=%q, want %q", got, want)
	}
	if got := dockerCreateRequestFor(setuid).HostConfig.SecurityOpt; len(got) != 0 {
		t.Fatalf("authority security options=%q, want no no-new-privileges", got)
	}
}

func TestDockerAdoptRejectsCapabilityMismatchedEffectiveFingerprint(t *testing.T) {
	spec := RuntimeSpec{
		RunID:                      "authority-volume-init-lineage",
		Image:                      "worker:latest",
		Entrypoint:                 []string{"install"},
		User:                       "0:0",
		Labels:                     map[string]string{"gh-agent-broker.run_id": "authority-volume-init-lineage"},
		Mounts:                     []Mount{{Source: "workspace", Target: "/lineage", Volume: true}},
		Network:                    NetworkPolicy{None: true},
		authorityVolumeInitializer: true,
	}
	exactDigest, err := runtimeSpecDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	zeroCapabilitySpec := spec
	zeroCapabilitySpec.authorityVolumeInitializer = false
	zeroCapabilityDigest, err := runtimeSpecDigest(zeroCapabilitySpec)
	if err != nil {
		t.Fatal(err)
	}
	chownOnly := effectiveRuntimeLaunchFingerprint{CreateRequest: dockerCreateRequestFor(spec)}
	chownOnly.CreateRequest.HostConfig.CapAdd = []string{"CHOWN"}
	chownOnlyDigest, err := effectiveRuntimeLaunchFingerprintDigest(chownOnly)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name        string
		labelDigest string
		wantError   bool
	}{
		{name: "zero capabilities", labelDigest: zeroCapabilityDigest, wantError: true},
		{name: "CHOWN without FOWNER", labelDigest: chownOnlyDigest, wantError: true},
		{name: "exact effective security class", labelDigest: exactDigest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"Id":"container-id","Name":"/sandbox-authority-volume-init-lineage","Image":"sha256:image","Config":{"Labels":{"gh-agent-broker.run_id":"authority-volume-init-lineage","gh-agent-broker.launch_spec":"` + tt.labelDigest + `"}},"State":{}}`
			backend := &DockerBackend{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet || req.URL.Path != "/containers/sandbox-authority-volume-init-lineage/json" {
					t.Fatalf("request=%s %s", req.Method, req.URL.Path)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}}
			info, err := backend.adopt(context.Background(), spec)
			if tt.wantError {
				if err == nil {
					t.Fatalf("adopted capability-mismatched container: %+v", info)
				}
				return
			}
			if err != nil || !info.Existing || info.ID != "container-id" {
				t.Fatalf("exact effective fingerprint adoption info=%+v err=%v", info, err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
