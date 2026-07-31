// Package codexauth owns the subscription credential used to mint short-lived,
// access-token-only Codex authentication bundles for sandbox runs.
package codexauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	CodexVersion = "0.146.0"
	// #nosec G101 -- reviewed public OAuth endpoint, not credential material.
	TokenEndpoint = "https://auth.openai.com/oauth/token"
	// ClientID is pinned from the reviewed @openai/codex 0.146.0 binary.
	ClientID = "app_EMoamEEZ73f0CkXaXp7hrann"

	defaultResponseLimit = 64 * 1024
)

type Config struct {
	MasterAuthPath string
	IssuanceRoot   string
	HTTPClient     *http.Client
	Now            func() time.Time
}

type Holder struct {
	cfg Config
	mu  sync.Mutex
}

type issuanceRecord struct {
	Version         string    `json:"version"`
	RunID           string    `json:"run_id"`
	CodexVersion    string    `json:"codex_version"`
	OAuthHost       string    `json:"token_host"`
	IssuedAt        time.Time `json:"issued_at"`
	ConsumedAt      time.Time `json:"consumed_at,omitempty"`
	State           string    `json:"state"`
	PreviousLineage string    `json:"previous_lineage,omitempty"`
	CurrentLineage  string    `json:"current_lineage,omitempty"`
}

type authFile struct {
	Tokens      authTokens                 `json:"tokens"`
	LastRefresh string                     `json:"last_refresh,omitempty"`
	Extra       map[string]json.RawMessage `json:"-"`
}

type authTokens struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    string `json:"account_id,omitempty"`
}

type refreshResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (a *authFile) UnmarshalJSON(data []byte) error {
	type knownAuthFile struct {
		Tokens      authTokens `json:"tokens"`
		LastRefresh string     `json:"last_refresh,omitempty"`
	}
	var known knownAuthFile
	if err := json.Unmarshal(data, &known); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	delete(fields, "tokens")
	delete(fields, "last_refresh")
	a.Tokens = known.Tokens
	a.LastRefresh = known.LastRefresh
	a.Extra = fields
	return nil
}

func (a authFile) MarshalJSON() ([]byte, error) {
	fields := make(map[string]json.RawMessage, len(a.Extra)+2)
	for key, value := range a.Extra {
		fields[key] = value
	}
	tokens, err := json.Marshal(a.Tokens)
	if err != nil {
		return nil, err
	}
	fields["tokens"] = tokens
	if a.LastRefresh != "" {
		lastRefresh, err := json.Marshal(a.LastRefresh)
		if err != nil {
			return nil, err
		}
		fields["last_refresh"] = lastRefresh
	}
	return json.Marshal(fields)
}

func New(cfg Config) (*Holder, error) {
	if !filepath.IsAbs(cfg.MasterAuthPath) || !filepath.IsAbs(cfg.IssuanceRoot) {
		return nil, fmt.Errorf("codex holder paths must be absolute")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	client := *cfg.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	cfg.HTTPClient = &client
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if err := secureDirectory(filepath.Dir(cfg.MasterAuthPath)); err != nil {
		return nil, fmt.Errorf("secure Codex master directory: %w", err)
	}
	if err := secureDirectory(cfg.IssuanceRoot); err != nil {
		return nil, fmt.Errorf("secure Codex issuance directory: %w", err)
	}
	if _, err := readMaster(cfg.MasterAuthPath); err != nil {
		return nil, err
	}
	return &Holder{cfg: cfg}, nil
}

// Issue returns a bounded access-only bundle in memory. Only token-free lineage
// state is durable, so credentials never enter the issuance tree.
func (h *Holder) Issue(ctx context.Context, runID string) ([]byte, error) {
	if !safeRunID(runID) {
		return nil, fmt.Errorf("invalid run ID")
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	lock, err := lockFile(h.cfg.MasterAuthPath + ".lock")
	if err != nil {
		return nil, err
	}
	defer unlockFile(lock)

	runDir := filepath.Join(h.cfg.IssuanceRoot, runID)
	recordPath := filepath.Join(runDir, "issuance.json")
	record, found, err := readRecord(recordPath)
	if err != nil {
		return nil, err
	}
	if found {
		if record.Version != "codex-run-issuance/v1" || record.RunID != runID ||
			record.CodexVersion != CodexVersion || record.OAuthHost != "auth.openai.com" ||
			record.State != "refresh_pending" && record.State != "issued" {
			return nil, fmt.Errorf("codex issuance state for run %q is invalid", runID)
		}
		if !record.ConsumedAt.IsZero() {
			return nil, fmt.Errorf("codex issuance for run %q was already consumed", runID)
		}
	}

	master, err := readMaster(h.cfg.MasterAuthPath)
	if err != nil {
		return nil, err
	}
	if !found {
		record = issuanceRecord{
			Version: "codex-run-issuance/v1", RunID: runID, CodexVersion: CodexVersion,
			OAuthHost: "auth.openai.com", State: "refresh_pending", PreviousLineage: master.LastRefresh,
		}
		if err := writeJSONAtomic(recordPath, record, 0o600); err != nil {
			return nil, err
		}
	}
	if record.State == "refresh_pending" && master.LastRefresh == record.PreviousLineage {
		refreshed, refreshErr := h.refresh(ctx, master.Tokens.RefreshToken)
		if refreshErr != nil {
			return nil, refreshErr
		}
		if refreshed.RefreshToken == "" {
			refreshed.RefreshToken = master.Tokens.RefreshToken
		}
		master.Tokens.AccessToken = refreshed.AccessToken
		master.Tokens.RefreshToken = refreshed.RefreshToken
		if refreshed.IDToken != "" {
			master.Tokens.IDToken = refreshed.IDToken
		}
		master.LastRefresh = h.cfg.Now().Format(time.RFC3339Nano)
		if err := writeJSONAtomic(h.cfg.MasterAuthPath, master, 0o600); err != nil {
			return nil, fmt.Errorf("persist rotated Codex master lineage: %w", err)
		}
	}
	if record.State == "issued" && record.CurrentLineage != master.LastRefresh {
		return nil, fmt.Errorf("codex issuance lineage for run %q is no longer current", runID)
	}

	bundle := authFile{
		Tokens: authTokens{
			AccessToken:  master.Tokens.AccessToken,
			RefreshToken: "",
			AccountID:    master.Tokens.AccountID,
		},
		LastRefresh: master.LastRefresh,
	}
	if record.State != "issued" {
		record.State = "issued"
		record.IssuedAt = h.cfg.Now()
		record.PreviousLineage = ""
		record.CurrentLineage = master.LastRefresh
		if err := writeJSONAtomic(recordPath, record, 0o600); err != nil {
			return nil, err
		}
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("encode Codex access bundle: %w", err)
	}
	if len(data) > defaultResponseLimit {
		return nil, fmt.Errorf("codex access bundle exceeds limit")
	}
	return append(data, '\n'), nil
}

func (h *Holder) Consume(runID string) error {
	return h.cleanup(runID, true)
}

func (h *Holder) Cleanup(runID string) error {
	return h.cleanup(runID, false)
}

func (h *Holder) cleanup(runID string, consumed bool) error {
	if !safeRunID(runID) {
		return fmt.Errorf("invalid run ID")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	runDir := filepath.Join(h.cfg.IssuanceRoot, runID)
	recordPath := filepath.Join(runDir, "issuance.json")
	var errs []error
	// Remove artifacts left by pre-injection versions. Current versions never
	// create this directory.
	if err := os.RemoveAll(filepath.Join(runDir, "capability")); err != nil {
		errs = append(errs, err)
	}
	record, found, err := readRecord(recordPath)
	if err != nil {
		errs = append(errs, err)
	} else if found && consumed && record.ConsumedAt.IsZero() {
		record.ConsumedAt = h.cfg.Now()
		if err := writeJSONAtomic(recordPath, record, 0o600); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (h *Holder) refresh(ctx context.Context, refreshToken string) (refreshResponse, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return refreshResponse{}, fmt.Errorf("codex master refresh token is missing")
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {ClientID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return refreshResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.cfg.HTTPClient.Do(req)
	if err != nil {
		return refreshResponse{}, fmt.Errorf("refresh Codex subscription access token: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultResponseLimit+1))
	if err != nil {
		return refreshResponse{}, fmt.Errorf("read Codex token response: %w", err)
	}
	if len(body) > defaultResponseLimit {
		return refreshResponse{}, fmt.Errorf("codex token response exceeds limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return refreshResponse{}, fmt.Errorf("codex token refresh returned HTTP %d", resp.StatusCode)
	}
	var out refreshResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return refreshResponse{}, fmt.Errorf("decode Codex token response: %w", err)
	}
	if out.AccessToken == "" {
		return refreshResponse{}, fmt.Errorf("codex token response is missing access_token")
	}
	return out, nil
}

func readMaster(path string) (authFile, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return authFile{}, fmt.Errorf("read Codex master auth: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return authFile{}, fmt.Errorf("codex master auth must be a mode-0600 regular file")
	}
	// #nosec G304 -- operator-reviewed absolute holder path.
	data, err := os.ReadFile(path)
	if err != nil {
		return authFile{}, err
	}
	var auth authFile
	if err := json.Unmarshal(data, &auth); err != nil {
		return authFile{}, fmt.Errorf("decode Codex master auth: %w", err)
	}
	if auth.Tokens.AccessToken == "" || auth.Tokens.RefreshToken == "" {
		return authFile{}, fmt.Errorf("codex master auth requires access_token and refresh_token")
	}
	return auth, nil
}

func readRecord(path string) (issuanceRecord, bool, error) {
	// #nosec G304 -- path is under the configured issuance root and validated run ID.
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return issuanceRecord{}, false, nil
	}
	if err != nil {
		return issuanceRecord{}, false, err
	}
	var record issuanceRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return issuanceRecord{}, false, fmt.Errorf("decode issuance record: %w", err)
	}
	return record, true, nil
}

func secureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	//nolint:gosec // G302: 0700 is the required strict mode for holder directories.
	return os.Chmod(path, 0o700)
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	if err := secureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".codex-holder-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if removeErr := os.Remove(tmpPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return errors.Join(err, dir.Close())
	}
	return dir.Close()
}

func lockFile(path string) (*os.File, error) {
	// #nosec G304 -- fixed sibling of the configured master path.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func unlockFile(file *os.File) {
	if file == nil {
		return
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		_ = file.Close() //nolint:errcheck // unlock failure is already unrecoverable during deferred cleanup.
		return
	}
	if err := file.Close(); err != nil {
		return
	}
}

func safeRunID(runID string) bool {
	if runID == "" || len(runID) > 160 || runID == "." || runID == ".." {
		return false
	}
	for _, r := range runID {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '_' || r == ':' || r == '-' {
			continue
		}
		return false
	}
	return true
}
