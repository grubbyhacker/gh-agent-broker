// Package api defines shared request and response DTOs for the broker API.
package api

import "encoding/json"

// CIObservationVersion identifies the stable CI observation projection consumed
// by Signal Plane. New fields may be added within this version; a semantic
// change to existing fields requires a new version.
const CIObservationVersion = "broker-ci-observation/v1"

type ErrorResponse struct {
	Code            string           `json:"code"`
	Message         string           `json:"message"`
	OperationID     string           `json:"operation_id,omitempty"`
	Decision        string           `json:"decision"`
	FailedChecks    []FailedCheck    `json:"failed_checks,omitempty"`
	RequiredChanges []RequiredChange `json:"required_changes,omitempty"`
	Warnings        []FailedCheck    `json:"warnings,omitempty"`
}

type FailedCheck struct {
	Dimension     string `json:"dimension"`
	Field         string `json:"field,omitempty"`
	Location      string `json:"location,omitempty"`
	Expected      string `json:"expected,omitempty"`
	Actual        string `json:"actual,omitempty"`
	SafeToDisplay bool   `json:"safe_to_display"`
	Message       string `json:"message"`
}

type RequiredChange struct {
	Field    string `json:"field,omitempty"`
	Location string `json:"location,omitempty"`
	Action   string `json:"action"`
}

type Metadata map[string]string

type DryRunRequest struct {
	AgentID     string   `json:"agent_id,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Repo        string   `json:"repo"`
	Repository  string   `json:"repository,omitempty"`
	Operation   string   `json:"operation"`
	Branch      string   `json:"branch,omitempty"`
	BaseBranch  string   `json:"base_branch,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Metadata    Metadata `json:"metadata,omitempty"`
}

type DryRunResponse struct {
	OperationID     string           `json:"operation_id"`
	Allowed         bool             `json:"allowed"`
	Decision        string           `json:"decision"`
	FailedChecks    []FailedCheck    `json:"failed_checks,omitempty"`
	Warnings        []FailedCheck    `json:"warnings,omitempty"`
	RequiredChanges []RequiredChange `json:"required_changes,omitempty"`
}

type PullCreateRequest struct {
	Title       string   `json:"title"`
	Head        string   `json:"head"`
	Base        string   `json:"base"`
	Body        string   `json:"body,omitempty"`
	Draft       bool     `json:"draft,omitempty"`
	Metadata    Metadata `json:"metadata,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type CommentCreateRequest struct {
	Body        string   `json:"body"`
	Metadata    Metadata `json:"metadata,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type IssueCreateRequest struct {
	Title       string   `json:"title"`
	Body        string   `json:"body"`
	Labels      []string `json:"labels,omitempty"`
	Metadata    Metadata `json:"metadata,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type IssueLabelsRequest struct {
	Labels      []string `json:"labels"`
	Metadata    Metadata `json:"metadata,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type PullReviewDismissRequest struct {
	Message     string   `json:"message"`
	Metadata    Metadata `json:"metadata,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type PullReviewThreadResolveRequest struct {
	Message     string   `json:"message"`
	Metadata    Metadata `json:"metadata,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type GitHubResult struct {
	URL       string `json:"url,omitempty"`
	HTMLURL   string `json:"html_url,omitempty"`
	Number    int    `json:"number,omitempty"`
	ID        int64  `json:"id,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

type PullSummary struct {
	ID             int64    `json:"id"`
	Number         int      `json:"number"`
	State          string   `json:"state"`
	Title          string   `json:"title"`
	Body           string   `json:"body,omitempty"`
	HeadRef        string   `json:"head_ref"`
	HeadSHA        string   `json:"head_sha"`
	BaseRef        string   `json:"base_ref"`
	Merged         bool     `json:"merged"`
	MergedAt       string   `json:"merged_at,omitempty"`
	Mergeable      *bool    `json:"mergeable,omitempty"`
	Author         string   `json:"author,omitempty"`
	Labels         []string `json:"labels,omitempty"`
	URL            string   `json:"url,omitempty"`
	HTMLURL        string   `json:"html_url,omitempty"`
	Comments       int      `json:"comments,omitempty"`
	ReviewComments int      `json:"review_comments,omitempty"`
}

type PullFile struct {
	Filename  string `json:"filename"`
	Status    string `json:"status"`
	SHA       string `json:"sha,omitempty"`
	Additions int    `json:"additions,omitempty"`
	Deletions int    `json:"deletions,omitempty"`
	Changes   int    `json:"changes,omitempty"`
	Patch     string `json:"patch,omitempty"`
}

type IssueSummary struct {
	ID            int64    `json:"id"`
	Number        int      `json:"number"`
	State         string   `json:"state"`
	Title         string   `json:"title"`
	Body          string   `json:"body,omitempty"`
	Author        string   `json:"author,omitempty"`
	Assignees     []string `json:"assignees,omitempty"`
	Labels        []string `json:"labels,omitempty"`
	URL           string   `json:"url,omitempty"`
	HTMLURL       string   `json:"html_url,omitempty"`
	IsPullRequest bool     `json:"is_pull_request,omitempty"`
}

type IssueComment struct {
	ID        int64  `json:"id"`
	Body      string `json:"body,omitempty"`
	Author    string `json:"author,omitempty"`
	URL       string `json:"url,omitempty"`
	HTMLURL   string `json:"html_url,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type UserRef struct {
	Login string `json:"login,omitempty"`
}

type PullReview struct {
	ID          string   `json:"id,omitempty"`
	DatabaseID  int64    `json:"database_id,omitempty"`
	State       string   `json:"state"`
	Body        string   `json:"body,omitempty"`
	Author      *UserRef `json:"author,omitempty"`
	CommitID    string   `json:"commit_id,omitempty"`
	SubmittedAt string   `json:"submitted_at,omitempty"`
	HTMLURL     string   `json:"html_url,omitempty"`
}

type PullReviewComment struct {
	ID         string   `json:"id,omitempty"`
	DatabaseID int64    `json:"database_id,omitempty"`
	Body       string   `json:"body,omitempty"`
	Author     *UserRef `json:"author,omitempty"`
	Path       string   `json:"path,omitempty"`
	Line       int      `json:"line,omitempty"`
	CommitID   string   `json:"commit_id,omitempty"`
	HTMLURL    string   `json:"html_url,omitempty"`
	CreatedAt  string   `json:"created_at,omitempty"`
	UpdatedAt  string   `json:"updated_at,omitempty"`
}

type PullReviewThread struct {
	ID                       string              `json:"id"`
	DatabaseID               int64               `json:"database_id,omitempty"`
	IsResolved               *bool               `json:"is_resolved,omitempty"`
	UnresolvedStateAvailable bool                `json:"unresolved_state_available"`
	Resolvable               bool                `json:"resolvable"`
	Path                     string              `json:"path,omitempty"`
	Line                     int                 `json:"line,omitempty"`
	Comments                 []PullReviewComment `json:"comments,omitempty"`
}

type PullReviewThreadResolveResult struct {
	ID         string `json:"id"`
	IsResolved bool   `json:"is_resolved"`
}

type CommitStatus struct {
	State      string          `json:"state"`
	SHA        string          `json:"sha,omitempty"`
	TotalCount int             `json:"total_count,omitempty"`
	Statuses   []StatusContext `json:"statuses,omitempty"`
}

type StatusContext struct {
	Context     string `json:"context"`
	State       string `json:"state"`
	Description string `json:"description,omitempty"`
	TargetURL   string `json:"target_url,omitempty"`
}

type CheckRuns struct {
	TotalCount int        `json:"total_count"`
	CheckRuns  []CheckRun `json:"check_runs"`
}

type CheckRun struct {
	ID          int64        `json:"id"`
	Name        string       `json:"name"`
	Status      string       `json:"status"`
	Conclusion  string       `json:"conclusion,omitempty"`
	HTMLURL     string       `json:"html_url,omitempty"`
	StartedAt   string       `json:"started_at,omitempty"`
	CompletedAt string       `json:"completed_at,omitempty"`
	Output      *CheckOutput `json:"output,omitempty"`
	App         *CheckApp    `json:"app,omitempty"`
}

// CheckApp identifies the GitHub App that produced a check run. A nil value
// means GitHub did not provide an app identity for that run.
type CheckApp struct {
	ID int64 `json:"id"`
}

// CheckOutput carries GitHub's bounded failure annotation summary. Individual
// annotations are intentionally fetched only when a check has failed.
type CheckOutput struct {
	Title       string            `json:"title,omitempty"`
	Summary     string            `json:"summary,omitempty"`
	Annotations []CheckAnnotation `json:"annotations,omitempty"`
}

type CheckAnnotation struct {
	Path            string `json:"path,omitempty"`
	StartLine       int    `json:"start_line,omitempty"`
	EndLine         int    `json:"end_line,omitempty"`
	AnnotationLevel string `json:"annotation_level,omitempty"`
	Message         string `json:"message,omitempty"`
}

// CIObservation is the broker's read-only, point-in-time view of the CI state
// for one pull request head. GitHub remains authoritative: this DTO deliberately
// does not calculate a separate required-check verdict.
type CIObservation struct {
	Version          string            `json:"version"`
	RequestedHeadSHA string            `json:"requested_head_sha"`
	Pull             PullSummary       `json:"pull"`
	CommitStatus     CommitStatus      `json:"commit_status"`
	CheckRuns        CheckRuns         `json:"check_runs"`
	WorkflowRuns     []WorkflowRun     `json:"workflow_runs"`
	WorkflowJobs     []WorkflowJob     `json:"workflow_jobs"`
	BranchProtection *BranchProtection `json:"branch_protection,omitempty"`
	BranchRules      *BranchRules      `json:"branch_rules,omitempty"`
	RequiredCI       []RequiredCI      `json:"required_ci"`
	AggregateState   string            `json:"aggregate_state"`
}

// RequiredCI is derived solely from the active GitHub branch rules. It is not
// a separately configured check-name allowlist.
type RequiredCI struct {
	Identity      string            `json:"identity"`
	Kind          string            `json:"kind"`
	IntegrationID *int64            `json:"integration_id,omitempty"`
	Workflow      *RequiredWorkflow `json:"workflow,omitempty"`
}

// RequiredWorkflow is GitHub's active required_workflows rule parameter.
// Path, ref, repository_id and sha together identify the workflow definition.
type RequiredWorkflow struct {
	Path         string `json:"path"`
	Ref          string `json:"ref"`
	RepositoryID int64  `json:"repository_id"`
	SHA          string `json:"sha"`
}

// BranchRules is GitHub's GET /repos/{owner}/{repo}/rules/branches/{branch}
// response. This endpoint needs only Metadata:read.
type BranchRules struct {
	Rules []BranchRule `json:"rules"`
}

// UnmarshalJSON accepts GitHub's active-rules envelope and the direct array
// returned by older endpoint versions without falling back to untyped maps.
func (r *BranchRules) UnmarshalJSON(b []byte) error {
	var direct []BranchRule
	if len(b) > 0 && b[0] == '[' {
		if err := json.Unmarshal(b, &direct); err != nil {
			return err
		}
		r.Rules = direct
		return nil
	}
	var envelope struct {
		Rules []BranchRule `json:"rules"`
	}
	if err := json.Unmarshal(b, &envelope); err != nil {
		return err
	}
	r.Rules = envelope.Rules
	return nil
}

type BranchRule struct {
	Type       string               `json:"type"`
	Parameters BranchRuleParameters `json:"parameters"`
}
type BranchRuleParameters struct {
	RequiredStatusChecks []RequiredStatusCheck `json:"required_status_checks,omitempty"`
	RequiredWorkflows    []RequiredWorkflow    `json:"required_workflows,omitempty"`
}
type RequiredStatusCheck struct {
	Context       string `json:"context"`
	IntegrationID *int64 `json:"integration_id,omitempty"`
}

// BranchProtection is the legacy protection fallback (Administration:read).
// It is optional because installations granted only Metadata:read cannot use it.
type BranchProtection struct {
	RequiredStatusChecks *LegacyRequiredStatusChecks `json:"required_status_checks,omitempty"`
}
type LegacyRequiredStatusChecks struct {
	Contexts []string              `json:"contexts,omitempty"`
	Checks   []RequiredStatusCheck `json:"checks,omitempty"`
}

type WorkflowRun struct {
	ID                  int64                `json:"id"`
	Name                string               `json:"name"`
	Status              string               `json:"status"`
	Conclusion          string               `json:"conclusion,omitempty"`
	HeadSHA             string               `json:"head_sha"`
	HTMLURL             string               `json:"html_url,omitempty"`
	CreatedAt           string               `json:"created_at,omitempty"`
	UpdatedAt           string               `json:"updated_at,omitempty"`
	Path                string               `json:"path,omitempty"`
	WorkflowID          int64                `json:"workflow_id,omitempty"`
	ReferencedWorkflows []ReferencedWorkflow `json:"referenced_workflows,omitempty"`
}

type ReferencedWorkflow struct {
	Path         string `json:"path,omitempty"`
	Ref          string `json:"ref,omitempty"`
	SHA          string `json:"sha,omitempty"`
	RepositoryID int64  `json:"repository_id,omitempty"`
}

type WorkflowJob struct {
	RunID       int64  `json:"run_id"`
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Conclusion  string `json:"conclusion,omitempty"`
	HeadSHA     string `json:"head_sha,omitempty"`
	HTMLURL     string `json:"html_url,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
}

// ActionsJobLog contains one complete log only when it is within the reviewed
// broker bound. It never contains a reusable GitHub URL or authorization data.
type ActionsJobLog struct {
	JobID     int64  `json:"job_id"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
	ByteLimit int64  `json:"byte_limit"`
	Text      string `json:"text"`
}
