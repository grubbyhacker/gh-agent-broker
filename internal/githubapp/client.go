// Package githubapp implements GitHub App JWT, token, and REST calls.
package githubapp

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
