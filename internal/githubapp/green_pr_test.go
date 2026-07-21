package githubapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gh-agent-broker/internal/config"
)

func TestGreenPRIdentityRequiresExactImmutableTargetAndHead(t *testing.T) {
	target := GreenPRRepositoryIdentity{DatabaseID: 42, NodeID: "R_42", FullName: "grubbyhacker/repository-worker-lifecycle-test"}
	for name, head := range map[string]GreenPRRepositoryIdentity{
		"matching":             target,
		"database ID mismatch": {DatabaseID: 43, NodeID: "R_42", FullName: target.FullName},
		"node ID mismatch":     {DatabaseID: 42, NodeID: "R_43", FullName: target.FullName},
		"full name mismatch":   {DatabaseID: 42, NodeID: "R_42", FullName: "fork/repository-worker-lifecycle-test"},
	} {
		t.Run(name, func(t *testing.T) {
			got := sameGreenPRIdentity(target, head)
			if got != (name == "matching") {
				t.Fatalf("identity match=%v", got)
			}
		})
	}
}

func TestGreenPRChecksPendingLegacyStatusRemainsPollable(t *testing.T) {
	sha := strings.Repeat("a", 40)
	c := greenPRTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/check-runs"):
			writeGreenPRTestJSON(t, w, map[string]any{"check_runs": []any{}})
		case strings.HasSuffix(r.URL.Path, "/status"):
			writeGreenPRTestJSON(t, w, map[string]any{"sha": sha, "statuses": []any{map[string]any{"context": "required", "state": "pending", "creator": map[string]any{"id": 1}}}})
		default:
			t.Fatalf("unexpected %s", r.URL.String())
		}
	})
	rows, err := c.greenPRChecks("default", 1, "owner/repo", sha, []greenPRRule{{Context: "required"}})
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Status != "pending" || rows[0].Conclusion != "" || greenPRVerdict(rows) != "pending" {
		t.Fatalf("pending status became terminal: %#v", rows[0])
	}
}

func TestObserveGreenPRSelectsApplicableEvaluationSHA(t *testing.T) {
	head, merge := strings.Repeat("a", 40), strings.Repeat("b", 40)
	for name, tc := range map[string]struct{ mergeStatus, wantBasis, wantVerdict string }{
		"head only uses head": {"absent", "head", "satisfied"},
		"test merge with applicable required result is selected": {"pending", "test_merge", "pending"},
	} {
		t.Run(name, func(t *testing.T) {
			c := greenPRTestClient(t, greenPRObservationHandler(t, head, merge, tc.mergeStatus, GreenPRRepositoryIdentity{DatabaseID: 42, NodeID: "R_42", FullName: "owner/repo"}))
			obs, err := c.ObserveGreenPR("default", GreenPRRequest{RegisteredTaskDigest: "sha256:task", BrokerOperationID: "operation", AppSlug: "app", InstallationID: 1, Repository: "owner/repo", BaseRef: "main", WorkerRef: "refs/heads/agent/fleiglabs-repo-agent/work", PushedHeadSHA: head})
			if err != nil {
				t.Fatal(err)
			}
			if obs.TargetRepository.DatabaseID != 42 || obs.EvaluationBasis != tc.wantBasis || obs.Verdict != tc.wantVerdict {
				t.Fatalf("observation=%#v", obs)
			}
		})
	}
}

func TestObserveGreenPRRefusesMismatchedHeadImmutableIdentity(t *testing.T) {
	head := strings.Repeat("a", 40)
	for name, identity := range map[string]GreenPRRepositoryIdentity{
		"database ID": {DatabaseID: 43, NodeID: "R_42", FullName: "owner/repo"},
		"node ID":     {DatabaseID: 42, NodeID: "R_43", FullName: "owner/repo"},
	} {
		t.Run(name, func(t *testing.T) {
			c := greenPRTestClient(t, greenPRObservationHandler(t, head, "", "absent", identity))
			obs, err := c.ObserveGreenPR("default", GreenPRRequest{RegisteredTaskDigest: "sha256:task", BrokerOperationID: "operation", AppSlug: "app", InstallationID: 1, Repository: "owner/repo", BaseRef: "main", WorkerRef: "refs/heads/agent/fleiglabs-repo-agent/work", PushedHeadSHA: head})
			if err != nil || obs.Verdict != "refused" {
				t.Fatalf("obs=%#v err=%v", obs, err)
			}
		})
	}
}

func TestGreenPRChecksReadsLaterPagesForDuplicates(t *testing.T) {
	sha := strings.Repeat("a", 40)
	c := greenPRTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			writeGreenPRTestJSON(t, w, map[string]any{"sha": sha, "statuses": []any{}})
			return
		}
		if r.URL.Query().Get("page") == "1" {
			rows := make([]any, 100)
			for i := range rows {
				rows[i] = map[string]any{"name": "other", "status": "completed", "conclusion": "success", "app": map[string]any{"id": 1}}
			}
			writeGreenPRTestJSON(t, w, map[string]any{"check_runs": rows})
			return
		}
		writeGreenPRTestJSON(t, w, map[string]any{"check_runs": []any{map[string]any{"name": "required", "status": "completed", "conclusion": "success", "app": map[string]any{"id": 1}}, map[string]any{"name": "required", "status": "completed", "conclusion": "success", "app": map[string]any{"id": 1}}}})
	})
	if _, err := c.greenPRChecks("default", 1, "owner/repo", sha, []greenPRRule{{Context: "required"}}); err == nil {
		t.Fatal("later-page duplicate was hidden")
	}
}

func TestSealGreenPRObservationBindsEveryBrokerField(t *testing.T) {
	obs := GreenPRObservation{Version: GreenPRObservationVersion, RegisteredTaskDigest: "sha256:task", BrokerOperationID: "operation-a", AppSlug: "fleiglabs-repo-agent", InstallationID: 146437790, Repository: "grubbyhacker/repository-worker-lifecycle-test", TargetRepository: GreenPRRepositoryIdentity{DatabaseID: 42, NodeID: "R_42", FullName: "grubbyhacker/repository-worker-lifecycle-test"}, BaseRef: "main", WorkerRef: "refs/heads/agent/fleiglabs-repo-agent/work", PushedHeadSHA: strings.Repeat("a", 40), RequiredChecks: []GreenPRRequiredCheck{}, Verdict: "missing", ObservedAt: "2026-07-20T00:00:00Z"}
	sealed, err := sealGreenPRObservation(obs)
	if err != nil || sealed.IntegrityDigest == "" {
		t.Fatalf("seal: %#v %v", sealed, err)
	}
	obs.TargetRepository.NodeID = "R_changed"
	changed, err := sealGreenPRObservation(obs)
	if err != nil || changed.IntegrityDigest == sealed.IntegrityDigest {
		t.Fatal("digest did not bind target identity")
	}
}

func greenPRTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return &Client{cfg: config.GitHubConfig{APIBaseURL: server.URL}, http: server.Client(), apps: map[string]*appClient{"default": {tokens: map[int64]cachedToken{1: {Token: "fixture", ExpireAt: time.Now().Add(time.Hour)}}}}}
}

func greenPRObservationHandler(t *testing.T, head, merge, mergeStatus string, headIdentity GreenPRRepositoryIdentity) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo":
			writeGreenPRTestJSON(t, w, GreenPRRepositoryIdentity{DatabaseID: 42, NodeID: "R_42", FullName: "owner/repo"})
		case "/repos/owner/repo/pulls":
			writeGreenPRTestJSON(t, w, []any{map[string]any{"id": 7, "node_id": "PR_7", "number": 7, "html_url": "https://example.test/pr/7", "state": "open", "draft": false, "base": map[string]any{"ref": "main"}, "head": map[string]any{"ref": "agent/fleiglabs-repo-agent/work", "sha": head, "repo": headIdentity}, "merge_commit_sha": merge}})
		case "/repos/owner/repo/rules/branches/main":
			writeGreenPRTestJSON(t, w, map[string]any{"rules": []any{map[string]any{"type": "required_status_checks", "parameters": map[string]any{"required_status_checks": []any{map[string]any{"context": "required"}}}}}})
		default:
			if strings.HasSuffix(r.URL.Path, "/check-runs") {
				writeGreenPRTestJSON(t, w, map[string]any{"check_runs": []any{}})
				return
			}
			if strings.HasSuffix(r.URL.Path, "/status") {
				state := "success"
				if strings.Contains(r.URL.Path, merge) {
					state = mergeStatus
				}
				statuses := []any{}
				if state != "absent" {
					statuses = append(statuses, map[string]any{"context": "required", "state": state, "creator": map[string]any{"id": 1}})
				}
				writeGreenPRTestJSON(t, w, map[string]any{"sha": strings.Split(r.URL.Path, "/")[5], "statuses": statuses})
				return
			}
			t.Fatalf("unexpected %s", r.URL.String())
		}
	}
}

func writeGreenPRTestJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}
