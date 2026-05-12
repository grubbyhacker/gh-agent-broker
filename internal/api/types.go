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
	Repo        string   `json:"repo"`
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

type GitHubResult struct {
	URL     string `json:"url,omitempty"`
	HTMLURL string `json:"html_url,omitempty"`
	Number  int    `json:"number,omitempty"`
	ID      int64  `json:"id,omitempty"`
}
