// Package api defines shared request and response DTOs for the broker API.
package api

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

type GitHubResult struct {
	URL     string `json:"url,omitempty"`
	HTMLURL string `json:"html_url,omitempty"`
	Number  int    `json:"number,omitempty"`
	ID      int64  `json:"id,omitempty"`
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

type PullReview struct {
	ID          int64  `json:"id"`
	State       string `json:"state"`
	Body        string `json:"body,omitempty"`
	Author      string `json:"author,omitempty"`
	CommitID    string `json:"commit_id,omitempty"`
	SubmittedAt string `json:"submitted_at,omitempty"`
	HTMLURL     string `json:"html_url,omitempty"`
}

type PullReviewComment struct {
	ID        int64  `json:"id"`
	Body      string `json:"body,omitempty"`
	Author    string `json:"author,omitempty"`
	Path      string `json:"path,omitempty"`
	CommitID  string `json:"commit_id,omitempty"`
	HTMLURL   string `json:"html_url,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type PullReviewThread struct {
	ID                       string              `json:"id"`
	IsResolved               *bool               `json:"is_resolved,omitempty"`
	UnresolvedStateAvailable bool                `json:"unresolved_state_available"`
	Comments                 []PullReviewComment `json:"comments,omitempty"`
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
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Conclusion  string `json:"conclusion,omitempty"`
	HTMLURL     string `json:"html_url,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
}
