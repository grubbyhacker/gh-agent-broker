package policy

import (
	"testing"

	"gh-agent-broker/internal/config"
)

func TestCheckDeniesMissingMetadataWithRequiredChange(t *testing.T) {
	agent := config.Agent{
		ID:             "a1",
		Enabled:        true,
		Repositories:   []string{"o/r"},
		Operations:     []string{"pull.create"},
		BaseBranches:   []string{"main"},
		BranchPatterns: []string{"^agent/a1/.+$"},
		MetadataAssertions: map[string]config.AssertionPolicy{
			"pull.create": {
				Mode: "enforce",
				Fields: []config.AssertionField{{
					Name:      "Run-Id",
					Required:  true,
					Locations: []string{"request"},
				}},
			},
		},
	}
	got := Check(Request{
		Agent:      agent,
		AgentID:    "a1",
		Repo:       "o/r",
		Operation:  "pull.create",
		Branch:     "agent/a1/test",
		BaseBranch: "main",
		Metadata:   map[string]string{},
	})
	if got.Allowed {
		t.Fatalf("expected denial")
	}
	if len(got.RequiredChanges) != 1 {
		t.Fatalf("expected required change, got %#v", got.RequiredChanges)
	}
}

func TestCheckWarnModeAllows(t *testing.T) {
	agent := config.Agent{
		ID:           "a1",
		Enabled:      true,
		Repositories: []string{"o/r"},
		Operations:   []string{"issue.comment"},
		MetadataAssertions: map[string]config.AssertionPolicy{
			"issue.comment": {
				Mode: "warn",
				Fields: []config.AssertionField{{
					Name:     "Run-Id",
					Required: true,
				}},
			},
		},
	}
	got := Check(Request{
		Agent:     agent,
		AgentID:   "a1",
		Repo:      "o/r",
		Operation: "issue.comment",
	})
	if !got.Allowed {
		t.Fatalf("expected allow with warning")
	}
	if got.Decision != DecisionWarn || len(got.Warnings) != 1 {
		t.Fatalf("expected warning decision, got %#v", got)
	}
}

func TestCheckDeniesPolicyDimensions(t *testing.T) {
	agent := config.Agent{
		ID:             "a1",
		Enabled:        true,
		Repositories:   []string{"o/r"},
		Operations:     []string{"git.receive-pack"},
		BaseBranches:   []string{"main"},
		BranchPatterns: []string{"^refs/heads/agent/a1/.+$"},
		Permissions:    []string{"contents:write"},
	}
	got := Check(Request{
		Agent:       agent,
		AgentID:     "a1",
		Repo:        "o/other",
		Operation:   "pull.create",
		Branch:      "refs/heads/main",
		BaseBranch:  "release",
		Permissions: []string{"issues:write"},
	})
	if got.Allowed {
		t.Fatalf("expected denial")
	}
	wantDimensions := map[string]bool{
		"repo":        false,
		"operation":   false,
		"branch":      false,
		"base_branch": false,
		"permission":  false,
	}
	for _, check := range got.FailedChecks {
		if _, ok := wantDimensions[check.Dimension]; ok {
			wantDimensions[check.Dimension] = true
		}
	}
	for dimension, seen := range wantDimensions {
		if !seen {
			t.Fatalf("missing failed check dimension %q in %#v", dimension, got.FailedChecks)
		}
	}
}
