// Package policy evaluates agent authorization and metadata assertions.
package policy

import (
	"fmt"
	"regexp"
	"strings"

	"gh-agent-broker/internal/api"
	"gh-agent-broker/internal/config"
)

const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionWarn  = "warn"
)

type Request struct {
	Agent       config.Agent
	AgentID     string
	Repo        string
	Operation   string
	Branch      string
	BaseBranch  string
	Permissions []string
	Metadata    map[string]string
	Locations   map[string]map[string]string
}

type Result struct {
	Allowed         bool
	Decision        string
	FailedChecks    []api.FailedCheck
	Warnings        []api.FailedCheck
	RequiredChanges []api.RequiredChange
}

func Check(req Request) Result {
	var res Result
	res.Allowed = true
	res.Decision = DecisionAllow

	if req.AgentID == "" || req.Agent.ID == "" || req.AgentID != req.Agent.ID || !req.Agent.Enabled {
		res.addFailure("agent", "", "", "enabled authenticated agent", req.AgentID, true, "agent is not enabled or does not match authenticated identity")
	}
	if !containsFold(req.Agent.Repositories, req.Repo) {
		res.addFailure("repo", "", "", "allowed repository", req.Repo, true, "repository is not allowed for this agent")
	}
	if !contains(req.Agent.Operations, req.Operation) {
		res.addFailure("operation", "", "", "allowed operation", req.Operation, true, "operation is not allowed for this agent")
	}
	if req.Branch != "" && len(req.Agent.BranchPatterns) > 0 && !matchesAny(req.Agent.BranchPatterns, req.Branch) {
		res.addFailure("branch", "", "", strings.Join(req.Agent.BranchPatterns, " OR "), req.Branch, true, "branch does not match an allowed pattern")
		res.RequiredChanges = append(res.RequiredChanges, api.RequiredChange{
			Location: "branch",
			Action:   "use a branch matching one of the allowed branch patterns",
		})
	}
	if req.BaseBranch != "" && len(req.Agent.BaseBranches) > 0 && !contains(req.Agent.BaseBranches, req.BaseBranch) {
		res.addFailure("base_branch", "", "", strings.Join(req.Agent.BaseBranches, ", "), req.BaseBranch, true, "base branch is not allowed for this agent")
		res.RequiredChanges = append(res.RequiredChanges, api.RequiredChange{
			Location: "base_branch",
			Action:   "use an allowed base branch",
		})
	}
	for _, p := range req.Permissions {
		if !contains(req.Agent.Permissions, p) {
			res.addFailure("permission", "", "", "permission in agent allowlist", p, true, "requested permission is not allowed for this agent")
		}
	}

	assertRes := checkAssertions(req)
	res.FailedChecks = append(res.FailedChecks, assertRes.FailedChecks...)
	res.Warnings = append(res.Warnings, assertRes.Warnings...)
	res.RequiredChanges = append(res.RequiredChanges, assertRes.RequiredChanges...)

	if len(res.FailedChecks) > 0 {
		res.Allowed = false
		res.Decision = DecisionDeny
	} else if len(res.Warnings) > 0 {
		res.Decision = DecisionWarn
	}
	return res
}

func (r *Result) addFailure(dimension, field, location, expected, actual string, safe bool, message string) {
	r.FailedChecks = append(r.FailedChecks, api.FailedCheck{
		Dimension:     dimension,
		Field:         field,
		Location:      location,
		Expected:      expected,
		Actual:        actual,
		SafeToDisplay: safe,
		Message:       message,
	})
}

func checkAssertions(req Request) Result {
	var res Result
	policies := assertionPolicies(req.Agent.MetadataAssertions, req.Operation)
	for _, ap := range policies {
		mode := strings.ToLower(strings.TrimSpace(ap.Mode))
		if mode == "" {
			mode = "enforce"
		}
		if mode == "off" {
			continue
		}
		for _, f := range ap.Fields {
			check := checkField(f, req)
			if check == nil {
				continue
			}
			if mode == "warn" {
				res.Warnings = append(res.Warnings, *check)
			} else {
				res.FailedChecks = append(res.FailedChecks, *check)
				res.RequiredChanges = append(res.RequiredChanges, requiredChangeFor(f, *check))
			}
		}
	}
	return res
}

func assertionPolicies(m map[string]config.AssertionPolicy, op string) []config.AssertionPolicy {
	if len(m) == 0 {
		return nil
	}
	var out []config.AssertionPolicy
	if ap, ok := m["*"]; ok {
		out = append(out, ap)
	}
	if ap, ok := m[op]; ok {
		out = append(out, ap)
	}
	return out
}

func checkField(f config.AssertionField, req Request) *api.FailedCheck {
	if f.Name == "" {
		return nil
	}
	locations := f.Locations
	if len(locations) == 0 {
		locations = []string{"request"}
	}
	for _, loc := range locations {
		values := valuesForLocation(loc, req)
		v, ok := values[f.Name]
		if !ok || v == "" {
			if f.Required {
				return &api.FailedCheck{
					Dimension:     "metadata",
					Field:         f.Name,
					Location:      loc,
					Expected:      "present",
					SafeToDisplay: true,
					Message:       fmt.Sprintf("required metadata field %q is missing from %s", f.Name, loc),
				}
			}
			continue
		}
		if f.Value != "" && v != f.Value {
			return &api.FailedCheck{
				Dimension:     "metadata",
				Field:         f.Name,
				Location:      loc,
				Expected:      f.Value,
				Actual:        v,
				SafeToDisplay: true,
				Message:       fmt.Sprintf("metadata field %q has an unexpected value", f.Name),
			}
		}
		if f.Pattern != "" {
			re, err := regexp.Compile(f.Pattern)
			if err != nil || !re.MatchString(v) {
				return &api.FailedCheck{
					Dimension:     "metadata",
					Field:         f.Name,
					Location:      loc,
					Expected:      "match " + f.Pattern,
					Actual:        v,
					SafeToDisplay: true,
					Message:       fmt.Sprintf("metadata field %q does not match the required pattern", f.Name),
				}
			}
		}
	}
	return nil
}

func valuesForLocation(loc string, req Request) map[string]string {
	if loc == "request" || loc == "" {
		return req.Metadata
	}
	if req.Locations != nil {
		if values, ok := req.Locations[loc]; ok {
			return values
		}
	}
	return map[string]string{}
}

func requiredChangeFor(f config.AssertionField, failed api.FailedCheck) api.RequiredChange {
	action := "supply valid metadata"
	if failed.Expected == "present" {
		action = "add the required metadata field"
	} else if failed.Expected != "" {
		action = "change the metadata field to satisfy: " + failed.Expected
	}
	return api.RequiredChange{
		Field:    f.Name,
		Location: failed.Location,
		Action:   action,
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

func containsFold(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

func matchesAny(patterns []string, value string) bool {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil && re.MatchString(value) {
			return true
		}
	}
	return false
}
