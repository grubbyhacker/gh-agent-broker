package reporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gh-agent-broker/internal/api"
)

func TestReportIssueCallsBrokerWithReporterIdentity(t *testing.T) {
	var sawRequest bool
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest = true
		if r.Method != http.MethodPost || r.URL.Path != "/v1/repos/owner/repo/issues" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "broker-reporter-01" || pass != "reporter-secret" {
			t.Fatalf("BasicAuth = %q/%q ok=%v", user, pass, ok)
		}
		var req api.IssueCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Title != "observed bug" || req.Body != "details" {
			t.Fatalf("issue title/body = %q/%q", req.Title, req.Body)
		}
		if !contains(req.Labels, "agent-reported") || !contains(req.Labels, "needs-triage") {
			t.Fatalf("labels = %v", req.Labels)
		}
		if req.Metadata["Agent-Id"] != "broker-reporter-01" || req.Metadata["Dedupe-Key"] != "owner/repo:bug" {
			t.Fatalf("metadata = %v", req.Metadata)
		}
		if !contains(req.Permissions, "issues:write") {
			t.Fatalf("permissions = %v", req.Permissions)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(api.GitHubResult{HTMLURL: "https://github.invalid/owner/repo/issues/1", Number: 1, ID: 99}); err != nil {
			t.Fatal(err)
		}
	}))
	defer broker.Close()

	svc := NewService(testConfig(broker.URL))
	out, err := svc.ReportIssue(ReportIssueInput{
		Repo:      "owner/repo",
		Title:     "observed bug",
		Body:      "details",
		DedupeKey: "owner/repo:bug",
		Labels:    []string{"needs-triage"},
	})
	if err != nil {
		t.Fatalf("ReportIssue() error = %v", err)
	}
	if !sawRequest {
		t.Fatalf("broker was not called")
	}
	if out.Number != 1 || out.ID != 99 {
		t.Fatalf("output = %+v", out)
	}
}

func TestReportIssueRejectsDisallowedInputs(t *testing.T) {
	svc := NewService(testConfig("http://broker.invalid"))
	tests := []struct {
		name string
		in   ReportIssueInput
		want string
	}{
		{
			name: "repo",
			in:   ReportIssueInput{Repo: "owner/other", Title: "t", Body: "b", DedupeKey: "k"},
			want: "allowlist",
		},
		{
			name: "dedupe",
			in:   ReportIssueInput{Repo: "owner/repo", Title: "t", Body: "b"},
			want: "dedupe_key",
		},
		{
			name: "label",
			in:   ReportIssueInput{Repo: "owner/repo", Title: "t", Body: "b", DedupeKey: "k", Labels: []string{"forbidden"}},
			want: "label",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ReportIssue(tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ReportIssue() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func testConfig(brokerURL string) Config {
	return Config{
		BrokerURL:         brokerURL,
		BrokerAgentID:     "broker-reporter-01",
		BrokerAgentSecret: "reporter-secret",
		Repositories:      []string{"owner/repo"},
		DefaultLabel:      "agent-reported",
		AllowedLabels:     []string{"needs-triage"},
		MaxTitleLength:    256,
		MaxBodyLength:     20000,
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
