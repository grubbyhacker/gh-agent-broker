// Package githubapp implements GitHub App JWT, token, and REST calls.
package githubapp

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gh-agent-broker/internal/api"
	"gh-agent-broker/internal/config"
	"gh-agent-broker/internal/pushtripwire"

	"github.com/golang-jwt/jwt/v4"
)

var githubSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (c *Client) GetRef(appName, repo, ref string, installationID int64) (string, bool, error) {
	if !strings.HasPrefix(ref, "refs/heads/") {
		return "", false, fmt.Errorf("unsupported ref namespace")
	}
	refName := strings.TrimPrefix(ref, "refs/")
	parts := strings.Split(refName, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	var out struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/git/ref/"+strings.Join(parts, "/"), installationID, nil, &out)
	if err != nil {
		var apiErr APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return "", false, nil
		}
		return "", false, err
	}
	if !githubSHAPattern.MatchString(out.Object.SHA) {
		return "", false, errors.New("github ref returned invalid object sha")
	}
	return out.Object.SHA, true, nil
}

func (c *Client) PushTripwireMaterial(appName string, installationID int64, req pushtripwire.MaterialRequest, baseRef string, bounds config.PushTripwireBounds) (pushtripwire.MaterialResponse, error) {
	out := pushtripwire.MaterialResponse{Version: pushtripwire.Version, DeliveryID: req.DeliveryID, Repository: req.Repository, Ref: req.Ref, Before: req.Before, After: req.After, Commits: []pushtripwire.Commit{}, Files: []pushtripwire.File{}}
	incomplete := func(code string) (pushtripwire.MaterialResponse, error) {
		out.Complete = false
		out.ReasonCode = code
		out.Commits = []pushtripwire.Commit{}
		out.Files = []pushtripwire.File{}
		return out, nil
	}
	compareBefore := req.Before
	if req.Before == strings.Repeat("0", 40) {
		var found bool
		var err error
		compareBefore, found, err = c.GetRef(appName, req.Repository, baseRef, installationID)
		if err != nil || !found {
			return incomplete("base_ref_unavailable")
		}
	}
	var comparison struct {
		TotalCommits int    `json:"total_commits"`
		Status       string `json:"status"`
		Commits      []struct {
			SHA string `json:"sha"`
		} `json:"commits"`
	}
	path := "/repos/" + req.Repository + "/compare/" + compareBefore + "..." + req.After + "?per_page=" + strconv.Itoa(bounds.MaxCommits)
	if err := c.doJSON(appName, http.MethodGet, path, installationID, nil, &comparison); err != nil {
		return incomplete("github_material_unavailable")
	}
	if comparison.TotalCommits > bounds.MaxCommits || len(comparison.Commits) > bounds.MaxCommits {
		return incomplete("commit_limit_exceeded")
	}
	if comparison.TotalCommits != len(comparison.Commits) {
		return incomplete("commit_history_incomplete")
	}
	statusAllowed := comparison.Status == "ahead" || (req.Before == strings.Repeat("0", 40) && comparison.Status == "diverged")
	if !statusAllowed || comparison.TotalCommits == 0 || comparison.Commits[len(comparison.Commits)-1].SHA != req.After {
		return incomplete("commit_history_incomplete")
	}
	type treeNode struct {
		Path, Type, SHA string
		Size            int64
	}
	treeCache := map[string]map[string]treeNode{}
	loadTree := func(treeSHA string) (map[string]treeNode, string) {
		if cached, ok := treeCache[treeSHA]; ok {
			return cached, ""
		}
		if !githubSHAPattern.MatchString(treeSHA) {
			return nil, "invalid_tree_material"
		}
		var tree struct {
			Truncated bool       `json:"truncated"`
			Tree      []treeNode `json:"tree"`
		}
		if err := c.doJSON(appName, http.MethodGet, "/repos/"+req.Repository+"/git/trees/"+treeSHA+"?recursive=1", installationID, nil, &tree); err != nil {
			return nil, "github_material_unavailable"
		}
		if tree.Truncated {
			return nil, "tree_material_incomplete"
		}
		mapped := make(map[string]treeNode, len(tree.Tree))
		for _, node := range tree.Tree {
			if node.Path == "" || len(node.Path) > 4096 || strings.ContainsRune(node.Path, '\x00') || (node.Type != "blob" && node.Type != "tree" && node.Type != "commit") {
				return nil, "invalid_tree_material"
			}
			mapped[node.Path] = node
		}
		treeCache[treeSHA] = mapped
		return mapped, ""
	}
	var total int64
	type blobMaterial struct {
		content string
		size    int64
	}
	blobCache := map[string]blobMaterial{}
	loadBlob := func(sha string) (string, int64, string) {
		if material, ok := blobCache[sha]; ok {
			return material.content, material.size, ""
		}
		if !githubSHAPattern.MatchString(sha) {
			return "", 0, "invalid_blob_material"
		}
		var blob struct {
			Content, Encoding string
			Size              int64
		}
		if err := c.doJSON(appName, http.MethodGet, "/repos/"+req.Repository+"/git/blobs/"+sha, installationID, nil, &blob); err != nil {
			return "", 0, "github_material_unavailable"
		}
		if blob.Encoding != "base64" || blob.Size < 0 || blob.Size > bounds.MaxBlobBytes {
			return "", 0, "blob_limit_exceeded"
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(blob.Content, "\n", ""))
		if err != nil || int64(len(decoded)) != blob.Size {
			return "", 0, "invalid_blob_material"
		}
		content := base64.StdEncoding.EncodeToString(decoded)
		blobCache[sha] = blobMaterial{content: content, size: int64(len(decoded))}
		return content, int64(len(decoded)), ""
	}
	changedPaths := 0
	for _, listed := range comparison.Commits {
		if !githubSHAPattern.MatchString(listed.SHA) {
			return incomplete("commit_history_incomplete")
		}
		var commit struct {
			SHA    string `json:"sha"`
			Commit struct {
				Message string `json:"message"`
				Tree    struct {
					SHA string `json:"sha"`
				} `json:"tree"`
			} `json:"commit"`
			Parents []struct {
				SHA string `json:"sha"`
			} `json:"parents"`
		}
		if err := c.doJSON(appName, http.MethodGet, "/repos/"+req.Repository+"/commits/"+listed.SHA, installationID, nil, &commit); err != nil {
			return incomplete("github_material_unavailable")
		}
		if commit.SHA != listed.SHA || len(commit.Parents) == 0 || int64(len(commit.Commit.Message)) > bounds.MaxCommitMessageBytes {
			return incomplete("commit_history_incomplete")
		}
		total += int64(len(commit.Commit.Message))
		if total > bounds.MaxTotalBytes {
			return incomplete("total_byte_limit_exceeded")
		}
		out.Commits = append(out.Commits, pushtripwire.Commit{SHA: commit.SHA, Message: commit.Commit.Message})
		var parent struct {
			Commit struct {
				Tree struct {
					SHA string `json:"sha"`
				} `json:"tree"`
			} `json:"commit"`
		}
		if err := c.doJSON(appName, http.MethodGet, "/repos/"+req.Repository+"/commits/"+commit.Parents[0].SHA, installationID, nil, &parent); err != nil {
			return incomplete("github_material_unavailable")
		}
		beforeTree, code := loadTree(parent.Commit.Tree.SHA)
		if code != "" {
			return incomplete(code)
		}
		afterTree, code := loadTree(commit.Commit.Tree.SHA)
		if code != "" {
			return incomplete(code)
		}
		paths := map[string]bool{}
		for path := range beforeTree {
			paths[path] = true
		}
		for path := range afterTree {
			paths[path] = true
		}
		orderedPaths := make([]string, 0, len(paths))
		for path := range paths {
			orderedPaths = append(orderedPaths, path)
		}
		sort.Strings(orderedPaths)
		for _, path := range orderedPaths {
			before, beforeOK := beforeTree[path]
			after, afterOK := afterTree[path]
			if beforeOK && afterOK && before.SHA == after.SHA && before.Type == after.Type {
				continue
			}
			if (beforeOK && before.Type != "blob") || (afterOK && after.Type != "blob") {
				return incomplete("unsupported_tree_material")
			}
			status := "modified"
			if !beforeOK {
				status = "added"
			}
			if !afterOK {
				status = "deleted"
			}
			if beforeOK {
				changedPaths++
				if changedPaths > bounds.MaxPaths {
					return incomplete("path_limit_exceeded")
				}
				content, size, code := loadBlob(before.SHA)
				if code != "" {
					return incomplete(code)
				}
				total += size
				if total > bounds.MaxTotalBytes {
					return incomplete("total_byte_limit_exceeded")
				}
				out.Files = append(out.Files, pushtripwire.File{CommitSHA: commit.SHA, Path: path, Side: "before", Status: status, BlobSHA: before.SHA, Size: size, ContentBase64: content})
			}
			if afterOK {
				changedPaths++
				if changedPaths > bounds.MaxPaths {
					return incomplete("path_limit_exceeded")
				}
				content, size, code := loadBlob(after.SHA)
				if code != "" {
					return incomplete(code)
				}
				total += size
				if total > bounds.MaxTotalBytes {
					return incomplete("total_byte_limit_exceeded")
				}
				out.Files = append(out.Files, pushtripwire.File{CommitSHA: commit.SHA, Path: path, Side: "after", Status: status, BlobSHA: after.SHA, Size: size, ContentBase64: content})
			}
		}
	}
	out.Bounds = pushtripwire.MaterialBounds{CommitCount: len(out.Commits), PathCount: changedPaths, TotalBytes: total}
	out.Complete = true
	return out, nil
}

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

type APIError struct {
	StatusCode int
	Body       string
}

func (e APIError) Error() string {
	return fmt.Sprintf("github api failed: status %d: %s", e.StatusCode, e.Body)
}

func (e APIError) RateLimited() bool {
	if e.StatusCode == http.StatusTooManyRequests {
		return true
	}
	body := strings.ToLower(e.Body)
	return strings.Contains(body, "rate limit") || strings.Contains(body, "secondary rate")
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
		return "", APIError{StatusCode: resp.StatusCode, Body: string(body)}
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
		ID        int64  `json:"id"`
		URL       string `json:"url"`
		HTMLURL   string `json:"html_url"`
		CreatedAt string `json:"created_at"`
	}
	if err := c.doJSON(appName, http.MethodPost, "/repos/"+repo+"/issues/"+issueNumber+"/comments", installationID, req, &out); err != nil {
		return nil, err
	}
	return &api.GitHubResult{ID: out.ID, URL: out.URL, HTMLURL: out.HTMLURL, CreatedAt: out.CreatedAt}, nil
}

func (c *Client) DismissPullReview(appName, repo string, installationID int64, number int, reviewID int64, message string) (api.PullReview, error) {
	current, err := c.GetPullReview(appName, repo, installationID, number, reviewID)
	if err == nil && strings.EqualFold(current.State, "DISMISSED") {
		return current, nil
	}
	req := map[string]string{"message": message}
	var out githubReview
	path := "/repos/" + repo + "/pulls/" + strconv.Itoa(number) + "/reviews/" + strconv.FormatInt(reviewID, 10) + "/dismissals"
	if err := c.doJSON(appName, http.MethodPut, path, installationID, req, &out); err != nil {
		return api.PullReview{}, err
	}
	return mapReview(out), nil
}

func (c *Client) GetPullReview(appName, repo string, installationID int64, number int, reviewID int64) (api.PullReview, error) {
	var out githubReview
	path := "/repos/" + repo + "/pulls/" + strconv.Itoa(number) + "/reviews/" + strconv.FormatInt(reviewID, 10)
	if err := c.doJSON(appName, http.MethodGet, path, installationID, nil, &out); err != nil {
		return api.PullReview{}, err
	}
	return mapReview(out), nil
}

func (c *Client) DismissPullReviewNode(appName string, installationID int64, reviewNodeID, message string) (api.PullReview, error) {
	current, err := c.GetPullReviewNode(appName, installationID, reviewNodeID)
	if err == nil && strings.EqualFold(current.State, "DISMISSED") {
		return current, nil
	}
	var out struct {
		DismissPullRequestReview struct {
			PullRequestReview graphqlReview `json:"pullRequestReview"`
		} `json:"dismissPullRequestReview"`
	}
	err = c.doGraphQL(appName, installationID, `mutation($reviewID: ID!, $message: String!) {
  dismissPullRequestReview(input: {pullRequestReviewId: $reviewID, message: $message}) {
    pullRequestReview { id databaseId state body url submittedAt author { login } }
  }
}`, map[string]interface{}{"reviewID": reviewNodeID, "message": message}, &out)
	if err != nil {
		return api.PullReview{}, err
	}
	return mapGraphQLReview(out.DismissPullRequestReview.PullRequestReview), nil
}

func (c *Client) GetPullReviewNode(appName string, installationID int64, reviewNodeID string) (api.PullReview, error) {
	var out struct {
		Node graphqlReview `json:"node"`
	}
	err := c.doGraphQL(appName, installationID, `query($reviewID: ID!) {
  node(id: $reviewID) {
    ... on PullRequestReview { id databaseId state body url submittedAt author { login } }
  }
}`, map[string]interface{}{"reviewID": reviewNodeID}, &out)
	if err != nil {
		return api.PullReview{}, err
	}
	if out.Node.ID == "" {
		return api.PullReview{}, fmt.Errorf("github graphql returned no pull request review for node %q", reviewNodeID)
	}
	return mapGraphQLReview(out.Node), nil
}

func (c *Client) AddIssueLabels(appName, repo string, installationID int64, number int, labels []string) ([]string, error) {
	req := map[string][]string{"labels": labels}
	var out []githubLabel
	if err := c.doJSON(appName, http.MethodPost, "/repos/"+repo+"/issues/"+strconv.Itoa(number)+"/labels", installationID, req, &out); err != nil {
		return nil, err
	}
	return labelNames(out), nil
}

func (c *Client) RemoveIssueLabel(appName, repo string, installationID int64, number int, label string) ([]string, error) {
	var out []githubLabel
	status, err := c.doJSONStatus(appName, http.MethodDelete, "/repos/"+repo+"/issues/"+strconv.Itoa(number)+"/labels/"+url.PathEscape(label), installationID, nil, &out)
	if err != nil {
		if status == http.StatusNotFound {
			return c.ListIssueLabels(appName, repo, installationID, number)
		}
		return nil, err
	}
	return labelNames(out), nil
}

func (c *Client) ListIssueLabels(appName, repo string, installationID int64, number int) ([]string, error) {
	var out []githubLabel
	if err := c.doJSON(appName, http.MethodGet, "/repos/"+repo+"/issues/"+strconv.Itoa(number)+"/labels", installationID, nil, &out); err != nil {
		return nil, err
	}
	return labelNames(out), nil
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
		reviews = append(reviews, mapReview(r))
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
	threads, err := c.listPullReviewThreadsGraphQL(appName, repo, installationID, number, query)
	if err == nil {
		return threads, nil
	}
	comments, err := c.ListPullReviewComments(appName, repo, installationID, number, query)
	if err != nil {
		return nil, err
	}
	threads = make([]api.PullReviewThread, 0, len(comments))
	for _, comment := range comments {
		threads = append(threads, api.PullReviewThread{
			ID:                       comment.ID,
			UnresolvedStateAvailable: false,
			Resolvable:               false,
			Comments:                 []api.PullReviewComment{comment},
		})
	}
	return threads, nil
}

func (c *Client) ResolvePullReviewThread(appName string, installationID int64, threadID, message string) (api.PullReviewThreadResolveResult, error) {
	current, err := c.GetPullReviewThread(appName, installationID, threadID)
	if err == nil && current.IsResolved != nil && *current.IsResolved {
		return api.PullReviewThreadResolveResult{ID: current.ID, IsResolved: true}, nil
	}
	if strings.TrimSpace(message) != "" {
		if err := c.AddPullReviewThreadReply(appName, installationID, threadID, message); err != nil {
			return api.PullReviewThreadResolveResult{}, err
		}
	}
	var out struct {
		ResolveReviewThread struct {
			Thread struct {
				ID         string `json:"id"`
				IsResolved bool   `json:"isResolved"`
			} `json:"thread"`
		} `json:"resolveReviewThread"`
	}
	err = c.doGraphQL(appName, installationID, `mutation($threadID: ID!) {
  resolveReviewThread(input: {threadId: $threadID}) {
    thread { id isResolved }
  }
}`, map[string]interface{}{"threadID": threadID}, &out)
	if err != nil {
		return api.PullReviewThreadResolveResult{}, err
	}
	return api.PullReviewThreadResolveResult{ID: out.ResolveReviewThread.Thread.ID, IsResolved: out.ResolveReviewThread.Thread.IsResolved}, nil
}

func (c *Client) AddPullReviewThreadReply(appName string, installationID int64, threadID, body string) error {
	var out struct {
		AddPullRequestReviewThreadReply struct {
			Comment struct {
				ID string `json:"id"`
			} `json:"comment"`
		} `json:"addPullRequestReviewThreadReply"`
	}
	return c.doGraphQL(appName, installationID, `mutation($threadID: ID!, $body: String!) {
  addPullRequestReviewThreadReply(input: {pullRequestReviewThreadId: $threadID, body: $body}) {
    comment { id }
  }
}`, map[string]interface{}{"threadID": threadID, "body": body}, &out)
}

func (c *Client) GetPullReviewThread(appName string, installationID int64, threadID string) (api.PullReviewThread, error) {
	var out struct {
		Node graphqlReviewThread `json:"node"`
	}
	err := c.doGraphQL(appName, installationID, `query($threadID: ID!) {
  node(id: $threadID) {
    ... on PullRequestReviewThread {
      id
      isResolved
      path
      line
      comments(first: 20) {
        nodes {
          id
          databaseId
          body
          author { login }
          path
          line
          url
          createdAt
          updatedAt
        }
      }
    }
  }
}`, map[string]interface{}{"threadID": threadID}, &out)
	if err != nil {
		return api.PullReviewThread{}, err
	}
	if out.Node.ID == "" {
		return api.PullReviewThread{}, fmt.Errorf("github graphql returned no review thread for node %q", threadID)
	}
	return mapGraphQLReviewThread(out.Node), nil
}

func (c *Client) listPullReviewThreadsGraphQL(appName, repo string, installationID int64, number int, query url.Values) ([]api.PullReviewThread, error) {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" {
		return nil, fmt.Errorf("repo must be owner/repo")
	}
	first := 30
	if raw := query.Get("per_page"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			first = n
		}
	}
	if first > 100 {
		first = 100
	}
	var out struct {
		Repository struct {
			PullRequest struct {
				ReviewThreads struct {
					Nodes []graphqlReviewThread `json:"nodes"`
				} `json:"reviewThreads"`
			} `json:"pullRequest"`
		} `json:"repository"`
	}
	err := c.doGraphQL(appName, installationID, `query($owner: String!, $repo: String!, $number: Int!, $first: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      reviewThreads(first: $first) {
        nodes {
          id
          isResolved
          path
          line
          comments(first: 20) {
            nodes {
              id
              databaseId
              body
              author { login }
              path
              line
              url
              createdAt
              updatedAt
            }
          }
        }
      }
    }
  }
}`, map[string]interface{}{"owner": owner, "repo": name, "number": number, "first": first}, &out)
	if err != nil {
		return nil, err
	}
	threads := make([]api.PullReviewThread, 0, len(out.Repository.PullRequest.ReviewThreads.Nodes))
	for _, node := range out.Repository.PullRequest.ReviewThreads.Nodes {
		threads = append(threads, mapGraphQLReviewThread(node))
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
	NodeID      string     `json:"node_id"`
	State       string     `json:"state"`
	Body        string     `json:"body"`
	User        githubUser `json:"user"`
	CommitID    string     `json:"commit_id"`
	SubmittedAt string     `json:"submitted_at"`
	HTMLURL     string     `json:"html_url"`
}

type githubReviewComment struct {
	ID        int64      `json:"id"`
	NodeID    string     `json:"node_id"`
	Body      string     `json:"body"`
	User      githubUser `json:"user"`
	Path      string     `json:"path"`
	Line      int        `json:"line"`
	CommitID  string     `json:"commit_id"`
	HTMLURL   string     `json:"html_url"`
	CreatedAt string     `json:"created_at"`
	UpdatedAt string     `json:"updated_at"`
}

type graphqlReview struct {
	ID          string `json:"id"`
	DatabaseID  int64  `json:"databaseId"`
	State       string `json:"state"`
	Body        string `json:"body"`
	URL         string `json:"url"`
	SubmittedAt string `json:"submittedAt"`
	Author      struct {
		Login string `json:"login"`
	} `json:"author"`
}

type graphqlReviewThread struct {
	ID         string `json:"id"`
	IsResolved bool   `json:"isResolved"`
	Path       string `json:"path"`
	Line       int    `json:"line"`
	Comments   struct {
		Nodes []graphqlReviewComment `json:"nodes"`
	} `json:"comments"`
}

type graphqlReviewComment struct {
	ID         string `json:"id"`
	DatabaseID int64  `json:"databaseId"`
	Body       string `json:"body"`
	Author     struct {
		Login string `json:"login"`
	} `json:"author"`
	Path      string `json:"path"`
	Line      int    `json:"line"`
	URL       string `json:"url"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
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

func mapReview(r githubReview) api.PullReview {
	id := r.NodeID
	if id == "" && r.ID != 0 {
		id = strconv.FormatInt(r.ID, 10)
	}
	return api.PullReview{
		ID:          id,
		DatabaseID:  r.ID,
		State:       r.State,
		Body:        r.Body,
		Author:      userRef(r.User.Login),
		CommitID:    r.CommitID,
		SubmittedAt: r.SubmittedAt,
		HTMLURL:     r.HTMLURL,
	}
}

func mapGraphQLReview(r graphqlReview) api.PullReview {
	return api.PullReview{
		ID:          r.ID,
		DatabaseID:  r.DatabaseID,
		State:       r.State,
		Body:        r.Body,
		Author:      userRef(r.Author.Login),
		SubmittedAt: r.SubmittedAt,
		HTMLURL:     r.URL,
	}
}

func mapReviewComments(in []githubReviewComment) []api.PullReviewComment {
	out := make([]api.PullReviewComment, 0, len(in))
	for _, comment := range in {
		id := comment.NodeID
		if id == "" && comment.ID != 0 {
			id = strconv.FormatInt(comment.ID, 10)
		}
		out = append(out, api.PullReviewComment{
			ID:         id,
			DatabaseID: comment.ID,
			Body:       comment.Body,
			Author:     userRef(comment.User.Login),
			Path:       comment.Path,
			Line:       comment.Line,
			CommitID:   comment.CommitID,
			HTMLURL:    comment.HTMLURL,
			CreatedAt:  comment.CreatedAt,
			UpdatedAt:  comment.UpdatedAt,
		})
	}
	return out
}

func mapGraphQLReviewThread(node graphqlReviewThread) api.PullReviewThread {
	resolved := node.IsResolved
	thread := api.PullReviewThread{
		ID:                       node.ID,
		IsResolved:               &resolved,
		UnresolvedStateAvailable: true,
		Resolvable:               true,
		Path:                     node.Path,
		Line:                     node.Line,
		Comments:                 make([]api.PullReviewComment, 0, len(node.Comments.Nodes)),
	}
	for _, comment := range node.Comments.Nodes {
		thread.Comments = append(thread.Comments, api.PullReviewComment{
			ID:         comment.ID,
			DatabaseID: comment.DatabaseID,
			Body:       comment.Body,
			Author:     userRef(comment.Author.Login),
			Path:       comment.Path,
			Line:       comment.Line,
			HTMLURL:    comment.URL,
			CreatedAt:  comment.CreatedAt,
			UpdatedAt:  comment.UpdatedAt,
		})
	}
	return thread
}

func userRef(login string) *api.UserRef {
	if login == "" {
		return nil
	}
	return &api.UserRef{Login: login}
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

type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (c *Client) doGraphQL(appName string, installationID int64, query string, variables map[string]interface{}, out interface{}) error {
	token, err := c.InstallationToken(appName, installationID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]interface{}{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.graphQLURL(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
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
		return fmt.Errorf("github graphql failed: status %d: %s", resp.StatusCode, string(b))
	}
	var raw graphQLResponse
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if len(raw.Errors) > 0 {
		return fmt.Errorf("github graphql failed: %s", raw.Errors[0].Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw.Data, out)
}

func (c *Client) graphQLURL() string {
	base := strings.TrimRight(c.cfg.APIBaseURL, "/")
	if strings.HasSuffix(base, "/api/v3") {
		return strings.TrimSuffix(base, "/api/v3") + "/api/graphql"
	}
	return base + "/graphql"
}

func (c *Client) doJSON(appName, method, path string, installationID int64, in interface{}, out interface{}) error {
	_, err := c.doJSONStatus(appName, method, path, installationID, in, out)
	return err
}

func (c *Client) doJSONStatus(appName, method, path string, installationID int64, in interface{}, out interface{}) (int, error) {
	token, err := c.InstallationToken(appName, installationID)
	if err != nil {
		return 0, err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.cfg.APIBaseURL, "/")+path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer closeBody(resp.Body)
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, APIError{StatusCode: resp.StatusCode, Body: string(b)}
	}
	if out == nil {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.Unmarshal(b, out)
}

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil {
		return
	}
}
