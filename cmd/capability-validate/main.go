// Command capability-validate is an offline checker for a per-run capability
// claims description. It reads a JSON file describing the claims
// (agent_type, mode, run_id, work_item_id, allowed_models, call_budget,
// token_budget, expiry), constructs the immutable Claims through the same
// invariants the broker will enforce, and runs the mechanism-independent
// PolicyEvaluator.Validate against a supplied or current time.
//
// It is inert: it verifies no signature and touches no live path — the
// signing/serialization mechanism is the undecided Stage-4 decision (see
// plans/agent-handoff.md). This validates the CLAIMS SEMANTICS only, which is
// useful for authoring fixtures and reasoning about expiry offline.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"gh-agent-broker/internal/capability"
)

type claimsDoc struct {
	AgentType     string   `json:"agent_type"`
	Mode          string   `json:"mode"`
	RunID         string   `json:"run_id"`
	WorkItemID    string   `json:"work_item_id"`
	AllowedModels []string `json:"allowed_models"`
	CallBudget    int64    `json:"call_budget"`
	TokenBudget   int64    `json:"token_budget"`
	Expiry        string   `json:"expiry"` // RFC3339
}

func main() {
	fs := flag.NewFlagSet("capability-validate", flag.ExitOnError)
	path := fs.String("claims", "", "path to a JSON claims description")
	nowStr := fs.String("now", "", "optional RFC3339 instant to validate against (default: current time)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}
	if *path == "" {
		fatal(fmt.Errorf("-claims is required"))
	}

	// #nosec G304 -- claims path is an explicit operator-supplied CLI flag.
	raw, err := os.ReadFile(*path)
	if err != nil {
		fatal(err)
	}
	var doc claimsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		fatal(fmt.Errorf("decode claims: %w", err))
	}
	expiry, err := time.Parse(time.RFC3339, doc.Expiry)
	if err != nil {
		fatal(fmt.Errorf("parse expiry: %w", err))
	}
	claims, err := capability.NewClaims(capability.ClaimsInput{
		AgentType:     doc.AgentType,
		Mode:          capability.Mode(doc.Mode),
		RunID:         doc.RunID,
		WorkItemID:    doc.WorkItemID,
		AllowedModels: doc.AllowedModels,
		CallBudget:    doc.CallBudget,
		TokenBudget:   doc.TokenBudget,
		Expiry:        expiry,
	})
	if err != nil {
		fatal(err)
	}

	now := time.Now()
	if *nowStr != "" {
		now, err = time.Parse(time.RFC3339, *nowStr)
		if err != nil {
			fatal(fmt.Errorf("parse -now: %w", err))
		}
	}
	if err := (capability.PolicyEvaluator{}).Validate(claims, now); err != nil {
		fatal(err)
	}
	fmt.Printf("ok: capability claims valid at %s (expires %s)\n",
		now.UTC().Format(time.RFC3339), claims.Expiry().Format(time.RFC3339))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
