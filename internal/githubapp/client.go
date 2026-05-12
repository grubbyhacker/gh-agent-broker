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
	cfg        config.GitHubConfig
	privateKey *rsa.PrivateKey
	http       *http.Client
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
	// #nosec G304 -- private key path is an operator-controlled broker config value.
	b, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(b)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:        cfg,
		privateKey: key,
		http:       &http.Client{Timeout: 60 * time.Second},
		tokens:     map[int64]cachedToken{},
	}, nil
}

func (c *Client) InstallationToken(installationID int64) (string, error) {
	c.mu.Lock()
	if tok, ok := c.tokens[installationID]; ok && time.Now().Before(tok.ExpireAt.Add(-60*time.Second)) {
		c.mu.Unlock()
		return tok.Token, nil
	}
	c.mu.Unlock()

	j, err := c.jwt()
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
	c.mu.Lock()
	c.tokens[installationID] = cachedToken{Token: tr.Token, ExpireAt: tr.ExpiresAt, ExpiresAt: tr.ExpiresAt.Format(time.RFC3339)}
	c.mu.Unlock()
	return tr.Token, nil
}

func (c *Client) jwt() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    fmt.Sprintf("%d", c.cfg.AppID),
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return t.SignedString(c.privateKey)
}

func (c *Client) GetRepo(repo string, installationID int64) (*api.GitHubResult, error) {
	var out struct {
		ID      int64  `json:"id"`
		HTMLURL string `json:"html_url"`
		URL     string `json:"url"`
	}
	if err := c.doJSON(http.MethodGet, "/repos/"+repo, installationID, nil, &out); err != nil {
		return nil, err
	}
	return &api.GitHubResult{ID: out.ID, URL: out.URL, HTMLURL: out.HTMLURL}, nil
}

func (c *Client) CreatePull(repo string, installationID int64, title, head, base, body string, draft bool) (*api.GitHubResult, error) {
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
	if err := c.doJSON(http.MethodPost, "/repos/"+repo+"/pulls", installationID, req, &out); err != nil {
		return nil, err
	}
	return &api.GitHubResult{ID: out.ID, Number: out.Number, URL: out.URL, HTMLURL: out.HTMLURL}, nil
}

func (c *Client) CreateIssueComment(repo string, issueNumber string, installationID int64, body string) (*api.GitHubResult, error) {
	req := map[string]interface{}{"body": body}
	var out struct {
		ID      int64  `json:"id"`
		URL     string `json:"url"`
		HTMLURL string `json:"html_url"`
	}
	if err := c.doJSON(http.MethodPost, "/repos/"+repo+"/issues/"+issueNumber+"/comments", installationID, req, &out); err != nil {
		return nil, err
	}
	return &api.GitHubResult{ID: out.ID, URL: out.URL, HTMLURL: out.HTMLURL}, nil
}

func (c *Client) doJSON(method, path string, installationID int64, in interface{}, out interface{}) error {
	token, err := c.InstallationToken(installationID)
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
