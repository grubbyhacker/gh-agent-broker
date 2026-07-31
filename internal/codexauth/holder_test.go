package codexauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestIssueProjectsCurrentMasterWithoutRefreshing(t *testing.T) {
	root := t.TempDir()
	masterPath := writeMaster(t, root, `{
		"auth_mode":"chatgpt",
		"tokens":{
			"access_token":"current-access",
			"refresh_token":"current-refresh",
			"account_id":"acct",
			"unknown_token_field":{"preserve":true}
		},
		"unknown_top_level":"preserve"
	}`)
	var requests atomic.Int32
	holder, err := New(Config{
		MasterAuthPath: masterPath,
		IssuanceRoot:   filepath.Join(root, "issuance"),
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			t.Fatal("Issue called the OAuth endpoint")
			return nil, context.Canceled
		})},
		Now: func() time.Time { return time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}

	first := issueBundle(t, holder, "run-1", "idempotency-1")
	second := issueBundle(t, holder, "run-2", "idempotency-2")
	if first.Tokens.AccessToken != "current-access" || second.Tokens.AccessToken != first.Tokens.AccessToken {
		t.Fatalf("two runs did not receive the same current access token: first=%+v second=%+v", first, second)
	}
	if requests.Load() != 0 {
		t.Fatalf("OAuth requests after two Issue calls = %d, want 0", requests.Load())
	}
	if first.Tokens.RefreshToken != "" || first.Tokens.IDToken != "" || first.Tokens.AccountID != "acct" {
		t.Fatalf("access projection = %+v", first)
	}

	replayed := issueBundle(t, holder, "run-1", "idempotency-1")
	if replayed.Tokens.AccessToken != "current-access" || requests.Load() != 0 {
		t.Fatalf("idempotent projection changed or refreshed: bundle=%+v requests=%d", replayed, requests.Load())
	}
	recordBytes, err := os.ReadFile(filepath.Join(root, "issuance", "run-1", "issuance.json")) //nolint:gosec // test-owned path.
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"current-access", "current-refresh", "auth.openai.com", "codex_version",
		"token_host", "lineage", "refresh_pending",
	} {
		if strings.Contains(string(recordBytes), forbidden) {
			t.Fatalf("issuance record contains forbidden credential/version state %q: %s", forbidden, recordBytes)
		}
	}
	for _, required := range []string{`"run_id"`, `"idempotency_key"`, `"issued_at"`} {
		if !strings.Contains(string(recordBytes), required) {
			t.Fatalf("issuance record missing %s: %s", required, recordBytes)
		}
	}
	if err := holder.Consume("run-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Issue(context.Background(), "run-1", "idempotency-1"); err == nil {
		t.Fatal("consumed issuance was reissued")
	}
}

func TestRefreshRotatesMasterThenIssueProjectsSubsequentAccess(t *testing.T) {
	root := t.TempDir()
	masterPath := writeMaster(t, root, `{
		"auth_mode":"chatgpt",
		"tokens":{
			"access_token":"old-access",
			"refresh_token":"old-refresh",
			"account_id":"acct",
			"unknown_token_field":{"preserve":true}
		},
		"unknown_top_level":"preserve"
	}`)
	var requests atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests.Add(1)
		if req.URL.String() != TokenEndpoint || req.Method != http.MethodPost {
			t.Fatalf("request = %s %s", req.Method, req.URL)
		}
		body, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		values := string(body)
		for _, required := range []string{"grant_type=refresh_token", "refresh_token=old-refresh", "client_id=" + ClientID} {
			if !strings.Contains(values, required) {
				t.Fatalf("refresh form %q missing %q", values, required)
			}
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"new-access","refresh_token":"new-refresh","id_token":"new-id"}`)),
		}, nil
	})}
	now := time.Date(2026, 7, 30, 12, 30, 0, 0, time.UTC)
	holder, err := New(Config{
		MasterAuthPath: masterPath, IssuanceRoot: filepath.Join(root, "issuance"),
		HTTPClient: client, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	before := issueBundle(t, holder, "run-before", "idempotency-before")
	if before.Tokens.AccessToken != "old-access" || requests.Load() != 0 {
		t.Fatalf("pre-refresh projection=%+v requests=%d", before, requests.Load())
	}
	if err := holder.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("OAuth requests after Refresh = %d, want 1", requests.Load())
	}
	after := issueBundle(t, holder, "run-after", "idempotency-after")
	if after.Tokens.AccessToken != "new-access" || requests.Load() != 1 {
		t.Fatalf("post-refresh projection=%+v requests=%d", after, requests.Load())
	}

	var master authFile
	readJSON(t, masterPath, &master)
	if master.Tokens.RefreshToken != "new-refresh" || master.Tokens.AccessToken != "new-access" ||
		master.Tokens.IDToken != "new-id" || master.LastRefresh != now.Format(time.RFC3339Nano) {
		t.Fatalf("persisted master = %+v", master)
	}
	var preservedTokenField map[string]bool
	if err := json.Unmarshal(master.Tokens.Extra["unknown_token_field"], &preservedTokenField); err != nil {
		t.Fatal(err)
	}
	if string(master.Extra["auth_mode"]) != `"chatgpt"` ||
		string(master.Extra["unknown_top_level"]) != `"preserve"` ||
		!preservedTokenField["preserve"] {
		t.Fatalf("refresh lost unknown master fields: master=%+v token_extra=%s", master.Extra, master.Tokens.Extra["unknown_token_field"])
	}
	info, err := os.Stat(masterPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("refreshed master mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestHolderRejectsUnsafeMasterModesAndRefreshErrorIsRedacted(t *testing.T) {
	root := t.TempDir()
	master := filepath.Join(root, "auth.json")
	//nolint:gosec // G306: intentionally unsafe mode verifies fail-closed holder validation.
	if err := os.WriteFile(master, []byte(`{"tokens":{"access_token":"a","refresh_token":"secret-refresh"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{MasterAuthPath: master, IssuanceRoot: filepath.Join(root, "issuance")}); err == nil {
		t.Fatal("accepted unsafe master mode")
	}

	if err := os.Chmod(master, 0o600); err != nil {
		t.Fatal(err)
	}
	holder, err := New(Config{
		MasterAuthPath: master, IssuanceRoot: filepath.Join(root, "issuance"),
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{"error":"secret-refresh must never be logged"}`)),
			}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = holder.Refresh(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret-refresh") {
		t.Fatalf("unsafe refresh error: %v", err)
	}
}

func issueBundle(t *testing.T, holder *Holder, runID, idempotencyKey string) authFile {
	t.Helper()
	bundleBytes, err := holder.Issue(context.Background(), runID, idempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	var bundle authFile
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func writeMaster(t *testing.T, root, contents string) string {
	t.Helper()
	masterDir := filepath.Join(root, "master")
	if err := os.Mkdir(masterDir, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(masterDir, "auth.json")
	if err := os.WriteFile(masterPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return masterPath
}

func readJSON(t *testing.T, path string, out any) {
	t.Helper()
	//nolint:gosec // G304: helper reads test-owned paths supplied by each test.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}
