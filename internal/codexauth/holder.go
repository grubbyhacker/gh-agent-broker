// Package codexauth maintains the subscription credential master and projects
// its current access fields into authentication bundles for sandbox runs.
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
	RunID          string    `json:"run_id"`
	IdempotencyKey string    `json:"idempotency_key"`
	IssuedAt       time.Time `json:"issued_at"`
	ConsumedAt     time.Time `json:"consumed_at,omitempty"`
}

type authFile struct {
	Tokens      authTokens                 `json:"tokens"`
	LastRefresh string                     `json:"last_refresh,omitempty"`
	Extra       map[string]json.RawMessage `json:"-"`
}

type authTokens struct {
	IDToken      string                     `json:"id_token,omitempty"`
	AccessToken  string                     `json:"access_token"`
	RefreshToken string                     `json:"refresh_token"`
	AccountID    string                     `json:"account_id,omitempty"`
	Extra        map[string]json.RawMessage `json:"-"`
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

func (a *authTokens) UnmarshalJSON(data []byte) error {
	type knownAuthTokens struct {
		IDToken      string `json:"id_token,omitempty"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		AccountID    string `json:"account_id,omitempty"`
	}
	var known knownAuthTokens
	if err := json.Unmarshal(data, &known); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	delete(fields, "id_token")
	delete(fields, "access_token")
	delete(fields, "refresh_token")
	delete(fields, "account_id")
	a.IDToken = known.IDToken
	a.AccessToken = known.AccessToken
	a.RefreshToken = known.RefreshToken
	a.AccountID = known.AccountID
	a.Extra = fields
	return nil
}

func (a authTokens) MarshalJSON() ([]byte, error) {
	fields := make(map[string]json.RawMessage, len(a.Extra)+4)
	for key, value := range a.Extra {
		fields[key] = value
	}
	for key, value := range map[string]string{
		"id_token": a.IDToken, "access_token": a.AccessToken,
		"refresh_token": a.RefreshToken, "account_id": a.AccountID,
	} {
		if value == "" && key != "access_token" && key != "refresh_token" {
			continue
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		fields[key] = encoded
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

// Refresh rotates and atomically persists the full credential master. It is
// deliberately separate from run admission and access projection.
func (h *Holder) Refresh(ctx context.Context) error {
	if err := lockMutex(ctx, &h.mu); err != nil {
		return fmt.Errorf("wait for Codex credential holder: %w", err)
	}
	defer h.mu.Unlock()

	lock, err := lockFile(ctx, h.cfg.MasterAuthPath+".lock")
	if err != nil {
		return err
	}
	defer unlockFile(lock)

	master, err := readMaster(h.cfg.MasterAuthPath)
	if err != nil {
		return err
	}
	refreshed, err := h.refresh(ctx, master.Tokens.RefreshToken)
	if err != nil {
		return err
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
		return fmt.Errorf("persist refreshed Codex credential master: %w", err)
	}
	return nil
}

// Issue returns a bounded projection of the currently persisted access fields
// in memory. It never refreshes the master or calls an OAuth endpoint.
func (h *Holder) Issue(ctx context.Context, runID, idempotencyKey string) ([]byte, error) {
	if !safeRunID(runID) || strings.TrimSpace(idempotencyKey) == "" || len(idempotencyKey) > 256 {
		return nil, fmt.Errorf("invalid run issuance identity")
	}
	if err := lockMutex(ctx, &h.mu); err != nil {
		return nil, fmt.Errorf("wait for Codex credential holder: %w", err)
	}
	defer h.mu.Unlock()

	lock, err := lockFile(ctx, h.cfg.MasterAuthPath+".lock")
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
		if record.RunID != runID || record.IdempotencyKey != idempotencyKey || record.IssuedAt.IsZero() {
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
			RunID: runID, IdempotencyKey: idempotencyKey, IssuedAt: h.cfg.Now(),
		}
		if err := writeJSONAtomic(recordPath, record, 0o600); err != nil {
			return nil, err
		}
	}

	bundle := authFile{
		Tokens: authTokens{
			IDToken:      master.Tokens.IDToken,
			AccessToken:  master.Tokens.AccessToken,
			RefreshToken: "",
			AccountID:    master.Tokens.AccountID,
		},
		LastRefresh: master.LastRefresh,
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
	if auth.Tokens.IDToken == "" || auth.Tokens.AccessToken == "" || auth.Tokens.RefreshToken == "" {
		return authFile{}, fmt.Errorf("codex master auth requires id_token, access_token, and refresh_token")
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

func lockMutex(ctx context.Context, mutex *sync.Mutex) error {
	for {
		if mutex.TryLock() {
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func lockFile(ctx context.Context, path string) (*os.File, error) {
	// #nosec G304 -- fixed sibling of the configured master path.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.Join(err, file.Close())
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errors.Join(ctx.Err(), file.Close())
		case <-timer.C:
		}
	}
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
