package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gh-agent-broker/internal/release"
)

const releaseTestReference = "example.com/coder@sha256:bafebd36189ad3688b7b3915ea55d461e0bfcfbdde11e54b0a123999fb6be50f"

func TestRESTReleasePromoteUsesActionScopedPromoterAndAuditsIdentity(t *testing.T) {
	registry := openRESTReleaseRegistry(t)
	cfg := releaseRESTConfig(t)
	handler := NewRESTHandlerWithReleaseRegistry(newRESTTestService(t, cfg, newFakeRuntime(), testAudit(t)), registry, nil)

	generation := publishRelease(t, handler, "publisher-secret")
	postRelease(t, handler, "/v1/releases/"+generation+"/promote", "promoter-secret", nil, http.StatusNoContent)

	entries, err := registry.AuditTrail(context.Background(), parseGeneration(t, generation))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || entries[len(entries)-1].Operation != release.OperationPromote || entries[len(entries)-1].Actor != "protected-main-promoter" {
		t.Fatalf("promotion audit entries = %+v", entries)
	}
}

func TestRESTReleasePromoteAndRollbackRequireSeparateActions(t *testing.T) {
	registry := openRESTReleaseRegistry(t)
	cfg := releaseRESTConfig(t)
	handler := NewRESTHandlerWithReleaseRegistry(newRESTTestService(t, cfg, newFakeRuntime(), testAudit(t)), registry, nil)

	postRelease(t, handler, "/v1/releases/1/promote", "publisher-secret", nil, http.StatusForbidden)
	postRelease(t, handler, "/v1/releases/agent-types/coder", "promoter-secret", []byte(`{"generation":1}`), http.StatusForbidden)
}

func TestRESTReleaseVerifyAndAcquireAreNotCallerRoutes(t *testing.T) {
	registry := openRESTReleaseRegistry(t)
	cfg := releaseRESTConfig(t)
	handler := NewRESTHandlerWithReleaseRegistry(newRESTTestService(t, cfg, newFakeRuntime(), testAudit(t)), registry, nil)
	for _, route := range []string{"/v1/releases/1/verify", "/v1/releases/1/acquire"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, restRequest(http.MethodPost, route, "publisher-secret", []byte(`{"requirements":{"platforms":["linux/arm64"]},"available":true}`)))
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d body=%s", route, response.Code, response.Body.String())
		}
	}
	if validOperatorAction("release.verify") || validOperatorAction("release.acquire") {
		t.Fatal("caller verification/acquisition actions must not be valid")
	}
}

func TestRESTReleaseOperationErrorsUseClientStatuses(t *testing.T) {
	cfg := releaseRESTConfig(t)
	for _, test := range []struct {
		name   string
		err    error
		code   string
		status int
	}{
		{name: "unknown agent type", err: release.ErrNoActiveRelease, code: "no_active_release", status: http.StatusConflict},
		{name: "unavailable image", err: release.ErrUnavailable, code: "release_unavailable", status: http.StatusConflict},
		{name: "non-monotonic generation", err: release.ErrNotMonotonic, code: "release_not_monotonic", status: http.StatusConflict},
		{name: "not promotable", err: release.ErrNotPromotable, code: "release_not_promotable", status: http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := NewRESTHandlerWithReleaseRegistry(newRESTTestService(t, cfg, newFakeRuntime(), testAudit(t)), releaseErrorRegistry{err: test.err}, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, restRequest(http.MethodPost, "/v1/releases/1/promote", "promoter-secret", nil))
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func releaseRESTConfig(t *testing.T) Config {
	t.Helper()
	cfg := restTestConfig(t)
	cfg.OperatorPrincipals = map[string]OperatorPrincipal{
		"publisher":               {Token: "publisher-secret", AllowedActions: []string{"release.publish"}},
		"protected-main-promoter": {Token: "promoter-secret", AllowedActions: []string{"release.promote"}},
		"rollback":                {Token: "rollback-secret", AllowedActions: []string{"release.rollback"}},
	}
	cfg.AgentReleasePolicies = map[string]AgentReleasePolicy{"coder": {ProvenanceFields: []string{"source_revision"}, Platforms: []string{"linux/amd64"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("release REST config validation: %v", err)
	}
	return cfg
}

func openRESTReleaseRegistry(t *testing.T) *release.Store {
	t.Helper()
	registry, err := release.Open(context.Background(), filepath.Join(t.TempDir(), "releases.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("close release registry: %v", err)
		}
	})
	return registry
}

func publishRelease(t *testing.T, handler http.Handler, token string) string {
	t.Helper()
	response := httptest.NewRecorder()
	body, contentType := releasePublishBody(t)
	req := restRequest(http.MethodPost, "/v1/releases/publish", token, body)
	req.Header.Set("Content-Type", contentType)
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", response.Code, response.Body.String())
	}
	var item release.Release
	if err := json.NewDecoder(response.Body).Decode(&item); err != nil {
		t.Fatal(err)
	}
	return stringGeneration(item.Generation)
}

func releasePublishBody(t *testing.T) ([]byte, string) {
	t.Helper()
	manifest := []byte(`{"schemaVersion":2}`)
	sum := sha256.Sum256(manifest)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if digest != releaseTestReference[strings.LastIndex(releaseTestReference, "@")+1:] {
		t.Fatalf("test reference digest must match OCI manifest")
	}
	var artifact bytes.Buffer
	tw := tar.NewWriter(&artifact)
	for name, contents := range map[string][]byte{
		"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`),
		"index.json": []byte(`{"schemaVersion":2,"manifests":[{"digest":"` + digest + `","size":` + strconv.Itoa(len(manifest)) + `,"platform":{"os":"linux","architecture":"amd64"}}]}`),
		"blobs/sha256/" + strings.TrimPrefix(digest, "sha256:"): manifest,
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for name, value := range map[string][]byte{"protocol": []byte(releasePublishProtocol), "metadata": []byte(`{"agent_type":"coder","image_reference":"` + releaseTestReference + `","provenance":{"source_revision":"abc123","platform":"linux/amd64"}}`), "artifact": artifact.Bytes()} {
		part, err := mw.CreateFormFile(name, name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(value); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), mw.FormDataContentType()
}

func postRelease(t *testing.T, handler http.Handler, path, token string, body []byte, want int) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, restRequest(http.MethodPost, path, token, body))
	if response.Code != want {
		t.Fatalf("POST %s status=%d want=%d body=%s", path, response.Code, want, response.Body.String())
	}
}

func parseGeneration(t *testing.T, value string) int64 {
	t.Helper()
	generation, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

func stringGeneration(generation int64) string { return strconv.FormatInt(generation, 10) }

type releaseErrorRegistry struct{ err error }

func (r releaseErrorRegistry) PublishCandidate(context.Context, string, string, release.Provenance, string) (release.Release, error) {
	return release.Release{}, r.err
}

func (r releaseErrorRegistry) VerifyAndMarkAvailable(context.Context, int64, release.Requirements, string, string, func(context.Context, release.Release) error) error {
	return r.err
}
func (r releaseErrorRegistry) Promote(context.Context, int64, string) error          { return r.err }
func (r releaseErrorRegistry) Rollback(context.Context, string, int64, string) error { return r.err }
