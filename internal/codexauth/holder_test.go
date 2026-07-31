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

func TestHolderRotatesMasterAndIssuesAccessTokenOnlyOnce(t *testing.T) {
	root := t.TempDir()
	masterDir := filepath.Join(root, "master")
	if err := os.Mkdir(masterDir, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(masterDir, "auth.json")
	if err := os.WriteFile(masterPath, []byte(`{"auth_mode":"chatgpt","tokens":{"access_token":"old-access","refresh_token":"old-refresh","account_id":"acct"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
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
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	holder, err := New(Config{MasterAuthPath: masterPath, IssuanceRoot: filepath.Join(root, "issuance"), HTTPClient: client, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	bundleBytes, err := holder.Issue(context.Background(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := holder.Issue(context.Background(), "run-1")
	if err != nil || string(replayed) != string(bundleBytes) || requests.Load() != 1 {
		t.Fatalf("replay bundle mismatch requests=%d err=%v", requests.Load(), err)
	}
	var bundle authFile
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Tokens.AccessToken != "new-access" || bundle.Tokens.RefreshToken != "" ||
		bundle.Tokens.IDToken != "" || bundle.Tokens.AccountID != "acct" {
		t.Fatalf("bundle = %+v", bundle)
	}
	var master authFile
	readJSON(t, masterPath, &master)
	if master.Tokens.RefreshToken != "new-refresh" || master.Tokens.AccessToken != "new-access" {
		t.Fatalf("master = %+v", master)
	}
	if string(master.Extra["auth_mode"]) != `"chatgpt"` {
		t.Fatalf("master lost pinned auth document fields: %+v", master.Extra)
	}
	//nolint:gosec // G304: test-owned path below t.TempDir.
	recordBytes, err := os.ReadFile(filepath.Join(root, "issuance", "run-1", "issuance.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"old-refresh", "new-refresh", "new-access", "new-id"} {
		if strings.Contains(string(recordBytes), secret) {
			t.Fatalf("issuance record leaked %q", secret)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "issuance", "run-1", "capability")); !os.IsNotExist(err) {
		t.Fatalf("holder created a host capability path: %v", err)
	}
	if err := holder.Consume("run-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Issue(context.Background(), "run-1"); err == nil {
		t.Fatal("consumed issuance was re-issued")
	}
}

func TestHolderRejectsUnsafeMasterModesAndDoesNotExposeRefreshErrorBody(t *testing.T) {
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
	_, err = holder.Issue(context.Background(), "run-error")
	if err == nil || strings.Contains(err.Error(), "secret-refresh") {
		t.Fatalf("unsafe refresh error: %v", err)
	}
}

func TestHolderRecoversCrashAfterMasterRotationWithoutRefreshingTwice(t *testing.T) {
	root := t.TempDir()
	masterDir := filepath.Join(root, "master")
	if err := os.Mkdir(masterDir, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(masterDir, "auth.json")
	if err := os.WriteFile(masterPath, []byte(`{
		"tokens":{"access_token":"rotated-access","refresh_token":"rotated-refresh"},
		"last_refresh":"2026-07-30T12:00:00Z"
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(root, "issuance", "run-recovery")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "issuance.json"), []byte(`{
		"version":"codex-run-issuance/v1","run_id":"run-recovery","codex_version":"0.146.0",
		"token_host":"auth.openai.com","state":"refresh_pending","previous_lineage":""
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("recovery unexpectedly refreshed the already-rotated lineage")
		return nil, context.Canceled
	})}
	holder, err := New(Config{MasterAuthPath: masterPath, IssuanceRoot: filepath.Join(root, "issuance"), HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	bundleBytes, err := holder.Issue(context.Background(), "run-recovery")
	if err != nil {
		t.Fatal(err)
	}
	var bundle authFile
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Tokens.AccessToken != "rotated-access" || bundle.Tokens.RefreshToken != "" {
		t.Fatalf("recovered bundle=%+v", bundle)
	}
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
