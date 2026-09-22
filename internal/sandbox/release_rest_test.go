package sandbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gh-agent-broker/internal/release"
)

const releaseTestReference = "example.com/coder@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestRESTReleasePromoteUsesActionScopedPromoterAndAuditsIdentity(t *testing.T) {
	registry := openRESTReleaseRegistry(t)
	cfg := releaseRESTConfig(t)
	handler := NewRESTHandlerWithReleaseRegistry(newRESTTestService(t, cfg, newFakeRuntime(), testAudit(t)), registry, nil)

	generation := publishRelease(t, handler, "publisher-secret")
	verifyRelease(t, handler, generation, "verifier-secret")
	postRelease(t, handler, "/v1/releases/"+generation+"/acquire", "acquirer-secret", nil, http.StatusNoContent)
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
		"verifier":                {Token: "verifier-secret", AllowedActions: []string{"release.verify"}},
		"acquirer":                {Token: "acquirer-secret", AllowedActions: []string{"release.acquire"}},
		"protected-main-promoter": {Token: "promoter-secret", AllowedActions: []string{"release.promote"}},
		"rollback":                {Token: "rollback-secret", AllowedActions: []string{"release.rollback"}},
	}
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
	handler.ServeHTTP(response, restRequest(http.MethodPost, "/v1/releases/publish", token, []byte(`{"agent_type":"coder","image_reference":"`+releaseTestReference+`","provenance":{"source_revision":"abc123","platform":"linux/amd64"}}`)))
	if response.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", response.Code, response.Body.String())
	}
	var item release.Release
	if err := json.NewDecoder(response.Body).Decode(&item); err != nil {
		t.Fatal(err)
	}
	return stringGeneration(item.Generation)
}

func verifyRelease(t *testing.T, handler http.Handler, generation, token string) {
	t.Helper()
	postRelease(t, handler, "/v1/releases/"+generation+"/verify", token, []byte(`{"requirements":{"provenance_fields":["source_revision"],"platforms":["linux/amd64"]}}`), http.StatusNoContent)
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

func (r releaseErrorRegistry) Verify(context.Context, int64, release.Requirements, string) error {
	return r.err
}
func (r releaseErrorRegistry) MarkAvailable(context.Context, int64, bool, string) error { return r.err }
func (r releaseErrorRegistry) Promote(context.Context, int64, string) error             { return r.err }
func (r releaseErrorRegistry) Rollback(context.Context, string, int64, string) error    { return r.err }
