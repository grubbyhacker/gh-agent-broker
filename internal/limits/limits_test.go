package limits

import (
	"path/filepath"
	"testing"

	"gh-agent-broker/internal/config"
)

func TestCheckAndReserveEnforcesRunAndClassBudgets(t *testing.T) {
	cfg := config.MutationLimitsConfig{
		StatePath:           filepath.Join(t.TempDir(), "limits.json"),
		RunMetadataField:    "YKM-Curator-Run",
		ActionMetadataField: "YKM-Curator-Action",
		MaxNewObjectsPerRun: 2,
		ClassLimits:         map[string]int{"upload": 1},
	}
	md := map[string]string{"YKM-Curator-Run": "cur-1", "YKM-Curator-Action": "upload"}
	decision, err := CheckAndReserve(cfg, "pull.create", md)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("first decision allowed = false: %#v", decision)
	}
	decision, err = CheckAndReserve(cfg, "pull.create", md)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.Class != "upload" {
		t.Fatalf("second decision = %#v, want upload budget denial", decision)
	}
	md["YKM-Curator-Action"] = "feedback"
	decision, err = CheckAndReserve(cfg, "issue.create", md)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("feedback decision allowed = false: %#v", decision)
	}
	decision, err = CheckAndReserve(cfg, "issue.create", md)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatalf("total budget decision allowed = true")
	}
}

func TestCheckAndReserveRequiresRunMetadataWhenEnabled(t *testing.T) {
	cfg := config.MutationLimitsConfig{
		StatePath:           filepath.Join(t.TempDir(), "limits.json"),
		RunMetadataField:    "YKM-Curator-Run",
		MaxNewObjectsPerRun: 1,
		OperationClasses:    map[string]string{"issue.create": "feedback"},
	}
	decision, err := CheckAndReserve(cfg, "issue.create", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatalf("decision allowed without run metadata")
	}
}
