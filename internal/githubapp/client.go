// Package githubapp implements GitHub App JWT, token, and REST calls.
package githubapp

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gh-agent-broker/internal/api"
	"gh-agent-broker/internal/config"

	"github.com/golang-jwt/jwt/v4"
)

type Client struct {
	cfg  config.GitHubConfig
	http *http.Client
	apps map[string]*appClient
}

type appClient struct {
	app        config.GitHubAppConfig
	privateKey *rsa.PrivateKey
	mu         sync.Mutex
	tokens     map[int64]cachedToken
}

type cachedToken struct {
	Token     string
	ExpireAt  time.Time
	ExpiresAt string
}

type tokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func New(cfg config.GitHubConfig) (*Client, error) {
	c := &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 60 * time.Second},
		apps: map[string]*appClient{},
	}
	for name, app := range cfg.AppContexts() {
		// #nosec G304 -- private key path is an operator-controlled broker config value.
		b, err := os.ReadFile(app.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read github app %q private key: %w", name, err)
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(b)
		if err != nil {
			return nil, fmt.Errorf("parse github app %q private key: %w", name, err)
		}
		c.apps[name] = &appClient{
			app:        app,
			privateKey: key,
			tokens:     map[int64]cachedToken{},
		}
	}
	return c, nil
}

func (c *Client) InstallationToken(appName string, installationID int64) (string, error) {
	app, err := c.app(appName)
	if err != nil {
		return "", err
	}
	app.mu.Lock()
	if tok, ok := app.tokens[installationID]; ok && time.Now().Before(tok.ExpireAt.Add(-60*time.Second)) {
		app.mu.Unlock()
		return tok.Token, nil
	}
	app.mu.Unlock()

	j, err := app.jwt()
	if err != nil {
		return "", err
	}
	url := strings.TrimRight(c.cfg.APIBaseURL, "/") + fmt.Sprintf("/app/installations/%d/access_tokens", installationID)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+j)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer closeBody(resp.Body)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github token exchange failed: status %d: %s", resp.StatusCode, string(body))
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", err
	}
	if tr.Token == "" {
		return "", fmt.Errorf("github token exchange returned empty token")
	}
	app.mu.Lock()
	app.tokens[installationID] = cachedToken{Token: tr.Token, ExpireAt: tr.ExpiresAt, ExpiresAt: tr.ExpiresAt.Format(time.RFC3339)}
	app.mu.Unlock()
	return tr.Token, nil
}

func (c *Client) app(name string) (*appClient, error) {
	if name == "" {
		name = "default"
	}
	app, ok := c.apps[name]
	if !ok {
		return nil, fmt.Errorf("github app context %q is not configured", name)
	}
	return app, nil
}

func (a *appClient) jwt() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    fmt.Sprintf("%d", a.app.AppID),
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return t.SignedString(a.privateKey)
}

func (c *Client) GetRepo(appName, repo string, installationID int64) (*api.GitHubResult, error) {
	var out struct {
		ID      int64  `json:"id"`
		HTMLURL string `json:"html_url"`
		URL     string `json:"url"`
	}
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo, installationID, nil, &out); err != nil {
		return nil, err
	}
	return &api.GitHubResult{ID: out.ID, URL: out.URL, HTMLURL: out.HTMLURL}, nil
}

func (c *Client) CreatePull(appName, repo string, installationID int64, title, head, base, body string, draft bool) (*api.GitHubResult, error) {
	req := map[string]interface{}{
		"title": title,
		"head":  head,
		"base":  base,
		"body":  body,
		"draft": draft,
	}
	var out struct {
		ID      int64  `json:"id"`
		Number  int    `json:"number"`
		URL     string `json:"url"`
		HTMLURL string `json:"html_url"`
	}
	if err := c.doJSON(appName, http.MethodPost, "/repos/"+repo+"/pulls", installationID, req, &out); err != nil {
		return nil, err
	}
	return &api.GitHubResult{ID: out.ID, Number: out.Number, URL: out.URL, HTMLURL: out.HTMLURL}, nil
}

func (c *Client) CreateIssue(appName, repo string, installationID int64, title, body string, labels []string) (*api.GitHubResult, error) {
	req := map[string]interface{}{
		"title": title,
		"body":  body,
	}
	if len(labels) > 0 {
		req["labels"] = labels
	}
	var out struct {
		ID      int64  `json:"id"`
		Number  int    `json:"number"`
		URL     string `json:"url"`
		HTMLURL string `json:"html_url"`
	}
	if err := c.doJSON(appName, http.MethodPost, "/repos/"+repo+"/issues", installationID, req, &out); err != nil {
		return nil, err
	}
	return &api.GitHubResult{ID: out.ID, Number: out.Number, URL: out.URL, HTMLURL: out.HTMLURL}, nil
}

func (c *Client) CreateIssueComment(appName, repo string, issueNumber string, installationID int64, body string) (*api.GitHubResult, error) {
	req := map[string]interface{}{"body": body}
	var out struct {
		ID      int64  `json:"id"`
		URL     string `json:"url"`
		HTMLURL string `json:"html_url"`
	}
	if err := c.doJSON(appName, http.MethodPost, "/repos/"+repo+"/issues/"+issueNumber+"/comments", installationID, req, &out); err != nil {
		return nil, err
	}
	return &api.GitHubResult{ID: out.ID, URL: out.URL, HTMLURL: out.HTMLURL}, nil
}

func (c *Client) ListPulls(appName, repo string, installationID int64, query url.Values) ([]api.PullSummary, error) {
	var out []githubPull
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/pulls?"+query.Encode(), installationID, nil, &out); err != nil {
		return nil, err
	}
	return mapPulls(out), nil
}

func (c *Client) GetPull(appName, repo string, installationID int64, number int) (api.PullSummary, error) {
	var out githubPull
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/pulls/"+strconv.Itoa(number), installationID, nil, &out); err != nil {
		return api.PullSummary{}, err
	}
	return mapPull(out), nil
}

func (c *Client) ListPullFiles(appName, repo string, installationID int64, number int, query url.Values) ([]api.PullFile, error) {
	var out []api.PullFile
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/pulls/"+strconv.Itoa(number)+"/files?"+query.Encode(), installationID, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) ListPullReviews(appName, repo string, installationID int64, number int, query url.Values) ([]api.PullReview, error) {
	var out []githubReview
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/pulls/"+strconv.Itoa(number)+"/reviews?"+query.Encode(), installationID, nil, &out); err != nil {
		return nil, err
	}
	reviews := make([]api.PullReview, 0, len(out))
	for _, r := range out {
		reviews = append(reviews, api.PullReview{
			ID:          r.ID,
			State:       r.State,
			Body:        r.Body,
			Author:      r.User.Login,
			CommitID:    r.CommitID,
			SubmittedAt: r.SubmittedAt,
			HTMLURL:     r.HTMLURL,
		})
	}
	return reviews, nil
}

func (c *Client) ListPullReviewComments(appName, repo string, installationID int64, number int, query url.Values) ([]api.PullReviewComment, error) {
	var out []githubReviewComment
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/pulls/"+strconv.Itoa(number)+"/comments?"+query.Encode(), installationID, nil, &out); err != nil {
		return nil, err
	}
	return mapReviewComments(out), nil
}

func (c *Client) ListPullReviewThreads(appName, repo string, installationID int64, number int, query url.Values) ([]api.PullReviewThread, error) {
	comments, err := c.ListPullReviewComments(appName, repo, installationID, number, query)
	if err != nil {
		return nil, err
	}
	threads := make([]api.PullReviewThread, 0, len(comments))
	for _, comment := range comments {
		threads = append(threads, api.PullReviewThread{
			ID:                       strconv.FormatInt(comment.ID, 10),
			UnresolvedStateAvailable: false,
			Comments:                 []api.PullReviewComment{comment},
		})
	}
	return threads, nil
}

func (c *Client) ListIssueComments(appName, repo string, installationID int64, number int, query url.Values) ([]api.IssueComment, error) {
	var out []githubIssueComment
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/issues/"+strconv.Itoa(number)+"/comments?"+query.Encode(), installationID, nil, &out); err != nil {
		return nil, err
	}
	return mapIssueComments(out), nil
}

func (c *Client) GetIssue(appName, repo string, installationID int64, number int) (api.IssueSummary, error) {
	var out githubIssue
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/issues/"+strconv.Itoa(number), installationID, nil, &out); err != nil {
		return api.IssueSummary{}, err
	}
	return mapIssue(out), nil
}

func (c *Client) ListIssues(appName, repo string, installationID int64, query url.Values) ([]api.IssueSummary, error) {
	var out []githubIssue
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/issues?"+query.Encode(), installationID, nil, &out); err != nil {
		return nil, err
	}
	issues := make([]api.IssueSummary, 0, len(out))
	for _, issue := range out {
		issues = append(issues, mapIssue(issue))
	}
	return issues, nil
}

func (c *Client) GetCommitStatus(appName, repo string, installationID int64, sha string) (api.CommitStatus, error) {
	var out struct {
		State      string              `json:"state"`
		SHA        string              `json:"sha"`
		TotalCount int                 `json:"total_count"`
		Statuses   []api.StatusContext `json:"statuses"`
	}
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/commits/"+url.PathEscape(sha)+"/status", installationID, nil, &out); err != nil {
		return api.CommitStatus{}, err
	}
	return api.CommitStatus{State: out.State, SHA: out.SHA, TotalCount: out.TotalCount, Statuses: out.Statuses}, nil
}

func (c *Client) ListCheckRuns(appName, repo string, installationID int64, sha string, query url.Values) (api.CheckRuns, error) {
	var out api.CheckRuns
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/commits/"+url.PathEscape(sha)+"/check-runs?"+query.Encode(), installationID, nil, &out); err != nil {
		return api.CheckRuns{}, err
	}
	return out, nil
}

type githubUser struct {
	Login string `json:"login"`
}

type githubLabel struct {
	Name string `json:"name"`
}

type githubBranchRef struct {
	Ref string `json:"ref"`
	SHA string `json:"sha"`
}

type githubPull struct {
	ID             int64           `json:"id"`
	Number         int             `json:"number"`
	State          string          `json:"state"`
	Title          string          `json:"title"`
	Body           string          `json:"body"`
	Head           githubBranchRef `json:"head"`
	Base           githubBranchRef `json:"base"`
	Merged         bool            `json:"merged"`
	MergedAt       string          `json:"merged_at"`
	Mergeable      *bool           `json:"mergeable"`
	User           githubUser      `json:"user"`
	Labels         []githubLabel   `json:"labels"`
	URL            string          `json:"url"`
	HTMLURL        string          `json:"html_url"`
	Comments       int             `json:"comments"`
	ReviewComments int             `json:"review_comments"`
}

type githubIssue struct {
	ID          int64         `json:"id"`
	Number      int           `json:"number"`
	State       string        `json:"state"`
	Title       string        `json:"title"`
	Body        string        `json:"body"`
	User        githubUser    `json:"user"`
	Assignees   []githubUser  `json:"assignees"`
	Labels      []githubLabel `json:"labels"`
	URL         string        `json:"url"`
	HTMLURL     string        `json:"html_url"`
	PullRequest *struct{}     `json:"pull_request"`
}

type githubIssueComment struct {
	ID        int64      `json:"id"`
	Body      string     `json:"body"`
	User      githubUser `json:"user"`
	URL       string     `json:"url"`
	HTMLURL   string     `json:"html_url"`
	CreatedAt string     `json:"created_at"`
	UpdatedAt string     `json:"updated_at"`
}

type githubReview struct {
	ID          int64      `json:"id"`
	State       string     `json:"state"`
	Body        string     `json:"body"`
	User        githubUser `json:"user"`
	CommitID    string     `json:"commit_id"`
	SubmittedAt string     `json:"submitted_at"`
	HTMLURL     string     `json:"html_url"`
}

type githubReviewComment struct {
	ID        int64      `json:"id"`
	Body      string     `json:"body"`
	User      githubUser `json:"user"`
	Path      string     `json:"path"`
	CommitID  string     `json:"commit_id"`
	HTMLURL   string     `json:"html_url"`
	CreatedAt string     `json:"created_at"`
	UpdatedAt string     `json:"updated_at"`
}

func mapPulls(in []githubPull) []api.PullSummary {
	out := make([]api.PullSummary, 0, len(in))
	for _, p := range in {
		out = append(out, mapPull(p))
	}
	return out
}

func mapPull(p githubPull) api.PullSummary {
	return api.PullSummary{
		ID:             p.ID,
		Number:         p.Number,
		State:          p.State,
		Title:          p.Title,
		Body:           p.Body,
		HeadRef:        p.Head.Ref,
		HeadSHA:        p.Head.SHA,
		BaseRef:        p.Base.Ref,
		Merged:         p.Merged || p.MergedAt != "",
		MergedAt:       p.MergedAt,
		Mergeable:      p.Mergeable,
		Author:         p.User.Login,
		Labels:         labelNames(p.Labels),
		URL:            p.URL,
		HTMLURL:        p.HTMLURL,
		Comments:       p.Comments,
		ReviewComments: p.ReviewComments,
	}
}

func mapIssue(issue githubIssue) api.IssueSummary {
	return api.IssueSummary{
		ID:            issue.ID,
		Number:        issue.Number,
		State:         issue.State,
		Title:         issue.Title,
		Body:          issue.Body,
		Author:        issue.User.Login,
		Assignees:     userLogins(issue.Assignees),
		Labels:        labelNames(issue.Labels),
		URL:           issue.URL,
		HTMLURL:       issue.HTMLURL,
		IsPullRequest: issue.PullRequest != nil,
	}
}

func mapIssueComments(in []githubIssueComment) []api.IssueComment {
	out := make([]api.IssueComment, 0, len(in))
	for _, comment := range in {
		out = append(out, api.IssueComment{
			ID:        comment.ID,
			Body:      comment.Body,
			Author:    comment.User.Login,
			URL:       comment.URL,
			HTMLURL:   comment.HTMLURL,
			CreatedAt: comment.CreatedAt,
			UpdatedAt: comment.UpdatedAt,
		})
	}
	return out
}

func mapReviewComments(in []githubReviewComment) []api.PullReviewComment {
	out := make([]api.PullReviewComment, 0, len(in))
	for _, comment := range in {
		out = append(out, api.PullReviewComment{
			ID:        comment.ID,
			Body:      comment.Body,
			Author:    comment.User.Login,
			Path:      comment.Path,
			CommitID:  comment.CommitID,
			HTMLURL:   comment.HTMLURL,
			CreatedAt: comment.CreatedAt,
			UpdatedAt: comment.UpdatedAt,
		})
	}
	return out
}

func labelNames(labels []githubLabel) []string {
	out := make([]string, 0, len(labels))
	for _, label := range labels {
		out = append(out, label.Name)
	}
	return out
}

func userLogins(users []githubUser) []string {
	out := make([]string, 0, len(users))
	for _, user := range users {
		out = append(out, user.Login)
	}
	return out
}

func (c *Client) doJSON(appName, method, path string, installationID int64, in interface{}, out interface{}) error {
	token, err := c.InstallationToken(appName, installationID)
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.cfg.APIBaseURL, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer closeBody(resp.Body)
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github api failed: status %d: %s", resp.StatusCode, string(b))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil {
		return
	}
}
