package githubapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const GreenPRObservationVersion = "github-green-pr-observation/v1"

// GreenPRRequest contains only values fixed by registered admission and the
// broker's smart-HTTP operation. It deliberately has no caller completion
// facts such as PR, check, evaluation SHA, or verdict.
type GreenPRRequest struct {
	RegisteredTaskDigest string
	BrokerOperationID    string
	AppSlug              string
	InstallationID       int64
	Repository           string
	BaseRef              string
	WorkerRef            string
	PushedHeadSHA        string
}

type GreenPRRepositoryIdentity struct {
	DatabaseID int64  `json:"database_id"`
	NodeID     string `json:"node_id"`
	FullName   string `json:"full_name"`
}

type GreenPRPullRequest struct {
	DatabaseID     int64                     `json:"database_id"`
	NodeID         string                    `json:"node_id"`
	Number         int                       `json:"number"`
	URL            string                    `json:"url"`
	State          string                    `json:"state"`
	Draft          bool                      `json:"draft"`
	BaseRef        string                    `json:"base_ref"`
	HeadRef        string                    `json:"head_ref"`
	HeadRepository GreenPRRepositoryIdentity `json:"head_repository"`
	HeadSHA        string                    `json:"head_sha"`
}

type GreenPRRequiredCheck struct {
	Context           string `json:"context"`
	ExpectedAppSource *int64 `json:"expected_app_source,omitempty"`
	Presence          string `json:"presence"`
	Status            string `json:"status"`
	Conclusion        string `json:"conclusion"`
	ObservedSHA       string `json:"observed_sha"`
}

// GreenPRObservation is the only positive completion fact the broker emits.
// IntegrityDigest is over every other serialized member.
type GreenPRObservation struct {
	Version              string                    `json:"version"`
	RegisteredTaskDigest string                    `json:"registered_task_digest"`
	BrokerOperationID    string                    `json:"broker_operation_id"`
	AppSlug              string                    `json:"app_slug"`
	InstallationID       int64                     `json:"installation_id"`
	Repository           string                    `json:"repository"`
	TargetRepository     GreenPRRepositoryIdentity `json:"target_repository"`
	BaseRef              string                    `json:"base_ref"`
	WorkerRef            string                    `json:"worker_ref"`
	PushedHeadSHA        string                    `json:"pushed_head_sha"`
	PullRequest          *GreenPRPullRequest       `json:"pull_request"`
	RequiredRulesDigest  string                    `json:"required_rules_digest"`
	EvaluationBasis      string                    `json:"evaluation_basis"`
	EvaluationSHA        string                    `json:"evaluation_sha"`
	RequiredChecks       []GreenPRRequiredCheck    `json:"required_checks"`
	Verdict              string                    `json:"verdict"`
	ObservedAt           string                    `json:"observed_at"`
	IntegrityDigest      string                    `json:"integrity_digest"`
}

type greenPRRule struct {
	Context       string
	IntegrationID *int64
}

// CreateReadyGreenPR creates the sole permitted ready PR for a registered
// pushed branch. Title, head, base, body and draft state are broker-derived.
func (c *Client) CreateReadyGreenPR(appName string, in GreenPRRequest) (GreenPRPullRequest, error) {
	if err := validGreenPRRequest(in); err != nil {
		return GreenPRPullRequest{}, err
	}
	branch := strings.TrimPrefix(in.WorkerRef, "refs/heads/")
	var created greenPRPull
	if err := c.doJSON(appName, http.MethodPost, "/repos/"+in.Repository+"/pulls", in.InstallationID, map[string]any{
		"title": "Agent task " + in.RegisteredTaskDigest,
		"head":  branch, "base": in.BaseRef, "body": "", "draft": false,
	}, &created); err != nil {
		return GreenPRPullRequest{}, err
	}
	if !validGreenPRRepository(derefGreenPRRepository(created.Head.Repo), in.Repository) || created.Base.Ref != in.BaseRef || created.Head.Ref != branch || created.Head.SHA != in.PushedHeadSHA || created.State != "open" || created.Draft {
		return GreenPRPullRequest{}, fmt.Errorf("created pull request does not match broker-owned branch operation")
	}
	return GreenPRPullRequest{DatabaseID: created.ID, NodeID: created.NodeID, Number: created.Number, URL: created.HTMLURL, State: created.State, Draft: created.Draft, BaseRef: created.Base.Ref, HeadRef: created.Head.Ref, HeadRepository: derefGreenPRRepository(created.Head.Repo), HeadSHA: created.Head.SHA}, nil
}

// ObserveGreenPR uses only the installation token held by this client. It
// binds an existing ready PR's required rules and check state to GitHub's exact
// evaluation SHA. It has no mutation side effect.
func (c *Client) ObserveGreenPR(appName string, in GreenPRRequest) (GreenPRObservation, error) {
	if err := validGreenPRRequest(in); err != nil {
		return GreenPRObservation{}, err
	}
	target, err := c.greenPRRepository(appName, in.InstallationID, in.Repository)
	if err != nil {
		return GreenPRObservation{}, err
	}
	owner, _, _ := strings.Cut(in.Repository, "/")
	branch := strings.TrimPrefix(in.WorkerRef, "refs/heads/")
	pull, found, err := c.greenPRPull(appName, in.InstallationID, in.Repository, owner+":"+branch)
	if err != nil {
		return GreenPRObservation{}, err
	}
	if !found {
		obs := newGreenPRObservation(in, target)
		obs.Verdict = "missing"
		return sealGreenPRObservation(obs)
	}
	obs := newGreenPRObservation(in, target)
	if pull.Draft {
		obs.PullRequest = &GreenPRPullRequest{DatabaseID: pull.ID, NodeID: pull.NodeID, Number: pull.Number, URL: pull.HTMLURL, State: pull.State, Draft: pull.Draft, BaseRef: pull.Base.Ref, HeadRef: pull.Head.Ref, HeadRepository: derefGreenPRRepository(pull.Head.Repo), HeadSHA: pull.Head.SHA}
		obs.Verdict = "draft"
		return sealGreenPRObservation(obs)
	}
	if !sameGreenPRIdentity(target, derefGreenPRRepository(pull.Head.Repo)) || pull.Base.Ref != in.BaseRef || pull.Head.Ref != branch || pull.Head.SHA != in.PushedHeadSHA || pull.State != "open" {
		obs.Verdict = "refused"
		return sealGreenPRObservation(obs)
	}
	obs.PullRequest = &GreenPRPullRequest{DatabaseID: pull.ID, NodeID: pull.NodeID, Number: pull.Number, URL: pull.HTMLURL, State: pull.State, Draft: pull.Draft, BaseRef: pull.Base.Ref, HeadRef: pull.Head.Ref, HeadRepository: *pull.Head.Repo, HeadSHA: pull.Head.SHA}
	rules, err := c.greenPRRules(appName, in.InstallationID, in.Repository, in.BaseRef)
	if err != nil {
		return GreenPRObservation{}, err
	}
	obs.RequiredRulesDigest = greenPRRulesDigest(rules)
	obs.EvaluationBasis, obs.EvaluationSHA = "head", pull.Head.SHA
	if githubSHAPattern.MatchString(pull.MergeCommitSHA) && pull.MergeCommitSHA != pull.Head.SHA {
		mergeChecks, err := c.greenPRChecks(appName, in.InstallationID, in.Repository, pull.MergeCommitSHA, rules)
		if err != nil {
			return GreenPRObservation{}, err
		}
		if greenPRChecksApplicable(mergeChecks) {
			obs.EvaluationBasis, obs.EvaluationSHA, obs.RequiredChecks = "test_merge", pull.MergeCommitSHA, mergeChecks
		}
	}
	if !githubSHAPattern.MatchString(obs.EvaluationSHA) {
		obs.Verdict = "refused"
		return sealGreenPRObservation(obs)
	}
	if obs.RequiredChecks == nil {
		checks, err := c.greenPRChecks(appName, in.InstallationID, in.Repository, obs.EvaluationSHA, rules)
		if err != nil {
			return GreenPRObservation{}, err
		}
		obs.RequiredChecks = checks
	}
	obs.Verdict = greenPRVerdict(obs.RequiredChecks)
	return sealGreenPRObservation(obs)
}

func newGreenPRObservation(in GreenPRRequest, target GreenPRRepositoryIdentity) GreenPRObservation {
	return GreenPRObservation{Version: GreenPRObservationVersion, RegisteredTaskDigest: in.RegisteredTaskDigest, BrokerOperationID: in.BrokerOperationID, AppSlug: in.AppSlug, InstallationID: in.InstallationID, Repository: in.Repository, TargetRepository: target, BaseRef: in.BaseRef, WorkerRef: in.WorkerRef, PushedHeadSHA: in.PushedHeadSHA, RequiredChecks: []GreenPRRequiredCheck{}, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
}

func derefGreenPRRepository(repo *GreenPRRepositoryIdentity) GreenPRRepositoryIdentity {
	if repo == nil {
		return GreenPRRepositoryIdentity{}
	}
	return *repo
}

func validGreenPRRequest(in GreenPRRequest) error {
	if in.RegisteredTaskDigest == "" || in.BrokerOperationID == "" || in.AppSlug == "" || in.InstallationID < 1 || !githubSHAPattern.MatchString(in.PushedHeadSHA) || !strings.HasPrefix(in.WorkerRef, "refs/heads/") || in.BaseRef == "" {
		return fmt.Errorf("broker-derived green PR request is invalid")
	}
	owner, name, ok := strings.Cut(in.Repository, "/")
	if !ok || owner == "" || name == "" || strings.Contains(in.Repository, "/") && strings.Count(in.Repository, "/") != 1 {
		return fmt.Errorf("repository identity is invalid")
	}
	return nil
}

type greenPRRef struct {
	Ref, SHA string
	Repo     *GreenPRRepositoryIdentity `json:"repo"`
}
type greenPRPull struct {
	ID             int64      `json:"id"`
	NodeID         string     `json:"node_id"`
	Number         int        `json:"number"`
	HTMLURL        string     `json:"html_url"`
	State          string     `json:"state"`
	Draft          bool       `json:"draft"`
	Base           greenPRRef `json:"base"`
	Head           greenPRRef `json:"head"`
	MergeCommitSHA string     `json:"merge_commit_sha"`
}

func (c *Client) greenPRPull(app string, installation int64, repo, head string) (greenPRPull, bool, error) {
	var pulls []greenPRPull
	q := url.Values{"state": {"open"}, "head": {head}, "per_page": {"100"}}
	if err := c.doJSON(app, http.MethodGet, "/repos/"+repo+"/pulls?"+q.Encode(), installation, nil, &pulls); err != nil {
		return greenPRPull{}, false, err
	}
	if len(pulls) == 0 {
		return greenPRPull{}, false, nil
	}
	if len(pulls) != 1 {
		return greenPRPull{}, false, fmt.Errorf("multiple open pull requests for broker branch")
	}
	return pulls[0], true, nil
}

func (c *Client) greenPRRepository(app string, installation int64, fullName string) (GreenPRRepositoryIdentity, error) {
	var target GreenPRRepositoryIdentity
	if err := c.doJSON(app, http.MethodGet, "/repos/"+fullName, installation, nil, &target); err != nil {
		return GreenPRRepositoryIdentity{}, err
	}
	if !validGreenPRRepository(target, fullName) {
		return GreenPRRepositoryIdentity{}, fmt.Errorf("GitHub target repository identity is invalid")
	}
	return target, nil
}

func (c *Client) greenPRRules(app string, installation int64, repo, base string) ([]greenPRRule, error) {
	var response struct {
		Rules []struct {
			Type       string `json:"type"`
			Parameters struct {
				RequiredStatusChecks []struct {
					Context       string `json:"context"`
					IntegrationID *int64 `json:"integration_id"`
				} `json:"required_status_checks"`
			} `json:"parameters"`
		} `json:"rules"`
	}
	if err := c.doJSON(app, http.MethodGet, "/repos/"+repo+"/rules/branches/"+url.PathEscape(base), installation, nil, &response); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []greenPRRule{}
	for _, rule := range response.Rules {
		if rule.Type == "required_status_checks" {
			for _, check := range rule.Parameters.RequiredStatusChecks {
				if check.Context == "" || seen[check.Context] {
					return nil, fmt.Errorf("active required rules are incomplete or duplicate")
				}
				seen[check.Context] = true
				out = append(out, greenPRRule{check.Context, check.IntegrationID})
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("active required rules are absent")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Context < out[j].Context })
	return out, nil
}

func (c *Client) greenPRChecks(app string, installation int64, repo, sha string, rules []greenPRRule) ([]GreenPRRequiredCheck, error) {
	type checkRun struct {
		Name       string `json:"name"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		App        struct {
			ID int64 `json:"id"`
		} `json:"app"`
	}
	type statusContext struct {
		Context string `json:"context"`
		State   string `json:"state"`
		Creator struct {
			ID int64 `json:"id"`
		} `json:"creator"`
	}
	checkRuns := []checkRun{}
	statuses := []statusContext{}
	for page := 1; ; page++ {
		var response struct {
			CheckRuns []checkRun `json:"check_runs"`
		}
		if err := c.doJSON(app, http.MethodGet, "/repos/"+repo+"/commits/"+url.PathEscape(sha)+"/check-runs?per_page=100&page="+strconv.Itoa(page), installation, nil, &response); err != nil {
			return nil, err
		}
		checkRuns = append(checkRuns, response.CheckRuns...)
		if len(response.CheckRuns) < 100 {
			break
		}
	}
	for page := 1; ; page++ {
		var status struct {
			SHA      string          `json:"sha"`
			Statuses []statusContext `json:"statuses"`
		}
		if err := c.doJSON(app, http.MethodGet, "/repos/"+repo+"/commits/"+url.PathEscape(sha)+"/status?per_page=100&page="+strconv.Itoa(page), installation, nil, &status); err != nil {
			return nil, err
		}
		if status.SHA != "" && status.SHA != sha {
			return nil, fmt.Errorf("commit status returned wrong evaluation SHA")
		}
		statuses = append(statuses, status.Statuses...)
		if len(status.Statuses) < 100 {
			break
		}
	}
	out := make([]GreenPRRequiredCheck, 0, len(rules))
	for _, rule := range rules {
		row := GreenPRRequiredCheck{Context: rule.Context, ExpectedAppSource: rule.IntegrationID, Presence: "absent", Status: "", Conclusion: "", ObservedSHA: sha}
		matches := 0
		for _, run := range checkRuns {
			if run.Name == rule.Context {
				if rule.IntegrationID != nil && run.App.ID != *rule.IntegrationID {
					return nil, fmt.Errorf("required check context %q has wrong App source", rule.Context)
				}
				matches++
				row.Presence, row.Status, row.Conclusion = "present", run.Status, run.Conclusion
			}
		}
		for _, context := range statuses {
			if context.Context == rule.Context {
				if rule.IntegrationID != nil && context.Creator.ID != *rule.IntegrationID {
					return nil, fmt.Errorf("required status context %q has wrong App source", rule.Context)
				}
				matches++
				row.Presence = "present"
				switch strings.ToLower(context.State) {
				case "success", "error", "failure":
					row.Status, row.Conclusion = "completed", context.State
				default:
					row.Status, row.Conclusion = "pending", ""
				}
			}
		}
		if matches > 1 {
			return nil, fmt.Errorf("duplicate required check context %q", rule.Context)
		}
		out = append(out, row)
	}
	return out, nil
}

func greenPRChecksApplicable(rows []GreenPRRequiredCheck) bool {
	for _, row := range rows {
		if row.Presence == "present" {
			return true
		}
	}
	return false
}

func greenPRVerdict(rows []GreenPRRequiredCheck) string {
	for _, row := range rows {
		if row.Presence == "absent" || row.Status != "completed" {
			return "pending"
		}
	}
	for _, row := range rows {
		switch strings.ToLower(row.Conclusion) {
		case "success", "skipped", "neutral":
		default:
			return "failed"
		}
	}
	return "satisfied"
}

func sameGreenPRIdentity(left, right GreenPRRepositoryIdentity) bool {
	return left.DatabaseID > 0 && left.NodeID != "" && left.FullName != "" && left.DatabaseID == right.DatabaseID && left.NodeID == right.NodeID && left.FullName == right.FullName
}

func validGreenPRRepository(repo GreenPRRepositoryIdentity, fullName string) bool {
	return repo.DatabaseID > 0 && repo.NodeID != "" && repo.FullName == fullName
}

func greenPRRulesDigest(rules []greenPRRule) string {
	var b strings.Builder
	for _, r := range rules {
		b.WriteString(r.Context)
		b.WriteByte(0)
		if r.IntegrationID != nil {
			b.WriteString(strconv.FormatInt(*r.IntegrationID, 10))
		}
		b.WriteByte('\n')
	}
	s := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(s[:])
}

func sealGreenPRObservation(obs GreenPRObservation) (GreenPRObservation, error) {
	obs.IntegrityDigest = ""
	b, err := json.Marshal(obs)
	if err != nil {
		return GreenPRObservation{}, err
	}
	sum := sha256.Sum256(b)
	obs.IntegrityDigest = "sha256:" + hex.EncodeToString(sum[:])
	return obs, nil
}
