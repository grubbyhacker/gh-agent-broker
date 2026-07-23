// c4-bilateral-broker-bootstrap starts the real broker for the C4 diagnostic
// seam. It is deliberately outside the production image build and accepts no
// caller-provided broker, authority, repository, or credential configuration.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gh-agent-broker/internal/config"
	"gh-agent-broker/internal/sandbox"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

const (
	backendEnv        = "C4_BILATERAL_BACKEND_URL"
	sharedRootEnv     = "C4_BILATERAL_SHARED_ROOT"
	privateKeyEnv     = "C4_BILATERAL_APP_PRIVATE_KEY_PATH"
	issuerEnv         = "C4_BILATERAL_APP_ISSUER"
	fixtureRepository = "grubbyhacker/repository-worker-lifecycle-test"
	fixtureBranch     = "agent/fleiglabs-repo-agent/fixture"
	brokerAlias       = "broker"
	brokerListen      = "0.0.0.0:8080"
	fixtureIssuer     = int64(4292923)
	stageLimit        = 16
)

type bootstrapInputs struct {
	BackendURL string
	SharedRoot string
	PrivateKey string
	Issuer     int64
}

type stageEvent struct {
	OperationID string `json:"operationId"`
	Stage       string `json:"stage"`
	Reason      string `json:"reason"`
}

type stageEvidence struct {
	Version string       `json:"version"`
	Events  []stageEvent `json:"events"`
}

// forwardedTransportEvidence is a bounded projection of one durable broker
// journal row. Unlike the adjacent audit-stage evidence, it is never
// synthesized from the audit log.
type forwardedTransportEvidence struct {
	Version       string `json:"version"`
	OperationID   string `json:"operationId"`
	Phase         string `json:"phase"`
	PhaseOrdinal  int    `json:"phaseOrdinal"`
	Method        string `json:"method"`
	Service       string `json:"service"`
	Repository    string `json:"repository"`
	RequestPath   string `json:"requestPath"`
	Decision      string `json:"decision"`
	OutcomeCode   string `json:"outcomeCode"`
	HTTPStatus    int    `json:"httpStatus"`
	BackendStatus int    `json:"backendStatus"`
}

func main() {
	inputs, err := readBootstrapInputs(func(name string) string { return os.Getenv(name) })
	if err != nil {
		fatal(err)
	}
	if err = run(inputs); err != nil {
		fatal(err)
	}
}

func run(inputs bootstrapInputs) error {
	stateRoot := "/var/lib/c4-bilateral-broker"
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return fmt.Errorf("create C4 broker state root: %w", err)
	}
	fixture, err := sandbox.BootstrapC4BilateralAuthorityFixture(contextBackground(), stateRoot)
	if err != nil {
		return err
	}
	configPath := filepath.Join(stateRoot, "broker.yaml")
	auditPath := filepath.Join(stateRoot, "broker-audit.jsonl")
	if err = writeBrokerConfig(configPath, inputs, fixture, auditPath); err != nil {
		return err
	}
	stages := newStageWriter(filepath.Join(inputs.SharedRoot, "broker-transport-stages.json"), filepath.Join(inputs.SharedRoot, "broker-forwarded-transport.json"), fixture.AuthorityStorePath)
	if err = stages.write(nil); err != nil {
		return err
	}
	if err = publishBootstrap(inputs, fixture); err != nil {
		return err
	}

	broker := exec.Command("/usr/local/bin/gh-agent-broker", "-config", configPath, "-allow-public-bind") // #nosec G204 -- fixed binary and fixed bootstrap-owned config path.
	broker.Stdout, broker.Stderr = os.Stdout, os.Stderr
	if err = broker.Start(); err != nil {
		return fmt.Errorf("start real C4 broker: %w", err)
	}
	go stages.follow(auditPath)
	if err = waitReady(); err != nil {
		_ = broker.Process.Kill()
		return err
	}
	return broker.Wait()
}

// contextBackground avoids making the fixture API depend on a caller-selected
// deadline or cancellation path. The bootstrap either reaches readiness or
// the container exits; the outer harness owns the bounded wait.
func contextBackground() context.Context { return context.Background() }

func readBootstrapInputs(getenv func(string) string) (bootstrapInputs, error) {
	inputs := bootstrapInputs{BackendURL: strings.TrimSpace(getenv(backendEnv)), SharedRoot: strings.TrimSpace(getenv(sharedRootEnv)), PrivateKey: strings.TrimSpace(getenv(privateKeyEnv))}
	issuer, err := strconv.ParseInt(strings.TrimSpace(getenv(issuerEnv)), 10, 64)
	if err != nil || issuer != fixtureIssuer {
		return bootstrapInputs{}, errors.New("C4 bootstrap App issuer is invalid")
	}
	inputs.Issuer = issuer
	if inputs.BackendURL != "http://c4-git-http-fixture:18080" {
		return bootstrapInputs{}, errors.New("C4 bootstrap backend URL is invalid")
	}
	u, err := url.Parse(inputs.BackendURL)
	if err != nil || u.Scheme != "http" || u.Host != "c4-git-http-fixture:18080" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return bootstrapInputs{}, errors.New("C4 bootstrap backend URL is invalid")
	}
	if inputs.SharedRoot != "/run/c4" || !filepath.IsAbs(inputs.SharedRoot) {
		return bootstrapInputs{}, errors.New("C4 bootstrap shared root is invalid")
	}
	if inputs.PrivateKey != "/run/c4-private/app-private.pem" || !filepath.IsAbs(inputs.PrivateKey) {
		return bootstrapInputs{}, errors.New("C4 bootstrap private-key path is invalid")
	}
	info, err := os.Stat(inputs.PrivateKey)
	if err != nil || !info.Mode().IsRegular() {
		return bootstrapInputs{}, errors.New("C4 bootstrap private key is unavailable")
	}
	return inputs, nil
}

func writeBrokerConfig(path string, inputs bootstrapInputs, fixture sandbox.C4BilateralAuthorityFixture, auditPath string) error {
	// The effect credential authenticates as its custody transport principal.
	// Keep that principal explicitly enabled under the same fixed C4 policy as
	// the profile agent; it is not a secret-bearing credential entry.
	gitAgent := config.Agent{Enabled: true, Secret: "c4-bootstrap-parent-policy-only", Repositories: []string{fixtureRepository}, Operations: []string{"git.upload-pack", "git.receive-pack"}, BranchPatterns: []string{`^refs/heads/agent/fleiglabs-repo-agent/[a-z0-9][a-z0-9-]{0,62}$`, `^agent/fleiglabs-repo-agent/[a-z0-9][a-z0-9-]{0,62}$`}, BaseBranches: []string{"main"}, Permissions: []string{"contents:read", "contents:write"}}
	profileAgent := gitAgent
	profileAgent.ID = fixture.ProfileAgentID
	transportAgent := gitAgent
	transportAgent.ID = "authority-worker-operator"
	cfg := config.Config{
		Server: config.ServerConfig{Listen: brokerListen}, Audit: config.AuditConfig{Path: auditPath},
		GitHub:               config.GitHubConfig{AppID: inputs.Issuer, PrivateKeyPath: inputs.PrivateKey, APIBaseURL: inputs.BackendURL, GitBaseURL: inputs.BackendURL, Installations: map[string]int64{fixtureRepository: 42}},
		TransportObservation: config.TransportObservationConfig{Enabled: true, AuthorityStorePath: fixture.AuthorityStorePath, ProfileAgentIDs: map[string]string{"general-writer-v1": fixture.ProfileAgentID}},
		Agents:               []config.Agent{profileAgent, transportAgent},
	}
	encoded, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode C4 broker config: %w", err)
	}
	return writeAtomic(path, encoded, 0o600)
}

func publishBootstrap(inputs bootstrapInputs, fixture sandbox.C4BilateralAuthorityFixture) error {
	if err := os.MkdirAll(inputs.SharedRoot, 0o700); err != nil {
		return fmt.Errorf("create C4 shared root: %w", err)
	}
	ip, err := c4ContainerIPv4()
	if err != nil {
		return err
	}
	contract, err := json.Marshal(struct {
		Version  string `json:"version"`
		Network  any    `json:"network"`
		SmartGit any    `json:"smartGit"`
	}{"broker/c4-bilateral-fixture/v1", map[string]string{"alias": brokerAlias, "ipv4Address": ip}, map[string]string{"remote": "http://broker:8080/git/" + fixtureRepository + ".git", "repository": fixtureRepository, "baseBranch": "main", "branchRef": fixtureBranch}})
	if err != nil {
		return fmt.Errorf("encode C4 fixture contract: %w", err)
	}
	credential := []byte("C4_BROKER_AGENT_ID=" + fixture.AgentID + "\nC4_BROKER_AGENT_SECRET=" + fixture.AgentSecret + "\n")
	contractPath := filepath.Join(inputs.SharedRoot, "broker-fixture.json")
	credentialPath := filepath.Join(inputs.SharedRoot, "agentd-git-transport.env")
	stagePath := filepath.Join(inputs.SharedRoot, "broker-transport-stages.json")
	if err = writeAtomic(contractPath, contract, 0o600); err != nil {
		return err
	}
	if err = writeAtomic(credentialPath, credential, 0o400); err != nil {
		return err
	}
	if err = os.Chown(credentialPath, 1000, 1000); err != nil {
		return fmt.Errorf("set C4 credential projection owner: %w", err)
	}
	stage, err := os.ReadFile(stagePath)
	if err != nil {
		return fmt.Errorf("read C4 initial stages: %w", err)
	}
	manifest, err := json.Marshal(struct {
		Version              string            `json:"version"`
		FixtureContract      map[string]string `json:"fixtureContract"`
		InitialStageEvidence map[string]string `json:"initialStageEvidence"`
		ForwardedTransport   map[string]string `json:"forwardedTransport"`
		Credential           map[string]string `json:"credential"`
	}{"broker/c4-bilateral-bootstrap/v1", map[string]string{"path": "broker-fixture.json", "sha256": sha256Digest(contract)}, map[string]string{"path": "broker-transport-stages.json", "sha256": sha256Digest(stage)}, map[string]string{"path": "broker-forwarded-transport.json", "version": "broker/c4-forwarded-transport/v1"}, map[string]string{"path": "agentd-git-transport.env", "mode": "0400"}})
	if err != nil {
		return fmt.Errorf("encode C4 bootstrap manifest: %w", err)
	}
	return writeAtomic(filepath.Join(inputs.SharedRoot, "broker-bootstrap.json"), manifest, 0o444)
}

func c4ContainerIPv4() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("enumerate C4 network interfaces: %w", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String(), nil
			}
		}
	}
	return "", errors.New("C4 broker IPv4 address is unavailable")
}

func waitReady() error {
	client := &http.Client{Timeout: time.Second}
	for attempt := 0; attempt < 12; attempt++ {
		response, err := client.Get("http://127.0.0.1:8080/readyz") // #nosec G107 -- fixed loopback readiness route for the child process.
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return errors.New("real C4 broker did not become ready")
}

type stageWriter struct {
	stagePath     string
	forwardedPath string
	authorityPath string
	mu            sync.Mutex
}

func newStageWriter(stagePath, forwardedPath, authorityPath string) *stageWriter {
	return &stageWriter{stagePath: stagePath, forwardedPath: forwardedPath, authorityPath: authorityPath}
}

func (w *stageWriter) follow(auditPath string) {
	for {
		events, err := stagesFromAudit(auditPath)
		if err == nil {
			_ = w.write(events)
			if evidence, projectionErr := forwardedEvidenceFromStages(context.Background(), w.authorityPath, events); projectionErr == nil {
				_ = w.writeForwarded(evidence)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (w *stageWriter) write(events []stageEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(events) > stageLimit {
		return errors.New("C4 stage evidence exceeds its fixed bound")
	}
	encoded, err := json.Marshal(stageEvidence{Version: "broker/c4-pre-admission-stages/v1", Events: events})
	if err != nil {
		return err
	}
	return writeAtomic(w.stagePath, encoded, 0o444)
}

func (w *stageWriter) writeForwarded(evidence forwardedTransportEvidence) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	return writeAtomic(w.forwardedPath, encoded, 0o444)
}

func stagesFromAudit(path string) ([]stageEvent, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the bootstrap-owned fixed audit path.
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var events []stageEvent
	scanner := bufio.NewScanner(io.LimitReader(f, 64<<10))
	for scanner.Scan() {
		var event struct {
			Operation   string `json:"operation"`
			OperationID string `json:"operation_id"`
			Extra       struct {
				RequestID string `json:"request_id"`
				Stage     string `json:"stage"`
				Reason    string `json:"reason"`
			} `json:"extra"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil || event.Operation != "repository_transport_stage" || event.OperationID != event.Extra.RequestID || !validOperationID(event.OperationID) || !validStage(event.Extra.Stage, event.Extra.Reason) {
			continue
		}
		events = append(events, stageEvent{OperationID: event.OperationID, Stage: event.Extra.Stage, Reason: event.Extra.Reason})
		if len(events) > stageLimit {
			return nil, errors.New("C4 stage evidence exceeds its fixed bound")
		}
	}
	return events, scanner.Err()
}

func validStage(stage, reason string) bool {
	switch stage {
	case "request_received", "basic_challenge", "helper_basic_seen", "authenticated_retry", "credential_accepted", "credential_rejected", "custody_barrier_committed", "custody_barrier_failed", "pre_admission_rejected":
	default:
		return false
	}
	if reason == "" || len(reason) > 256 {
		return false
	}
	for _, r := range reason {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

func validOperationID(value string) bool {
	if value == "op-unknown" {
		return true
	}
	if len(value) != len("op-")+32 || !strings.HasPrefix(value, "op-") {
		return false
	}
	for _, char := range value[len("op-"):] {
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

// forwardedEvidenceFromStages retains audit stages independently, then finds
// the effect-custody stage's correlated durable forwarded row. The two sources
// must share the broker-generated operation ID; a missing row is a failure,
// never evidence synthesized from the audit record.
func forwardedEvidenceFromStages(ctx context.Context, authorityPath string, stages []stageEvent) (forwardedTransportEvidence, error) {
	var operationID string
	for _, stage := range stages {
		if stage.Stage != "custody_barrier_committed" {
			continue
		}
		if operationID != "" && operationID != stage.OperationID {
			return forwardedTransportEvidence{}, errors.New("C4 audit has multiple custody-barrier operations")
		}
		operationID = stage.OperationID
	}
	if operationID == "" {
		return forwardedTransportEvidence{}, errors.New("C4 audit has no committed custody-barrier operation")
	}
	if !filepath.IsAbs(authorityPath) || !validOperationID(operationID) {
		return forwardedTransportEvidence{}, errors.New("C4 forwarded transport correlation is invalid")
	}
	storeURL := (&url.URL{Scheme: "file", Path: authorityPath, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", storeURL)
	if err != nil {
		return forwardedTransportEvidence{}, fmt.Errorf("open C4 transport journal: %w", err)
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT operation_id,phase,phase_ordinal,method,service,repository,request_path,decision,outcome_code,http_status,backend_status FROM repository_transport_events WHERE operation_id=? AND phase='forwarded' ORDER BY phase_ordinal`, operationID)
	if err != nil {
		return forwardedTransportEvidence{}, fmt.Errorf("read C4 forwarded transport row: %w", err)
	}
	defer rows.Close()
	var evidence forwardedTransportEvidence
	count := 0
	for rows.Next() {
		if err = rows.Scan(&evidence.OperationID, &evidence.Phase, &evidence.PhaseOrdinal, &evidence.Method, &evidence.Service, &evidence.Repository, &evidence.RequestPath, &evidence.Decision, &evidence.OutcomeCode, &evidence.HTTPStatus, &evidence.BackendStatus); err != nil {
			return forwardedTransportEvidence{}, fmt.Errorf("scan C4 forwarded transport row: %w", err)
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return forwardedTransportEvidence{}, fmt.Errorf("iterate C4 forwarded transport row: %w", err)
	}
	if count != 1 {
		return forwardedTransportEvidence{}, errors.New("C4 correlated forwarded transport row is absent or ambiguous")
	}
	if evidence.OperationID != operationID || evidence.Phase != "forwarded" || evidence.PhaseOrdinal != 2 || evidence.Method != http.MethodGet || evidence.Service != "git-upload-pack" || evidence.Repository != fixtureRepository || evidence.RequestPath != "/git/"+fixtureRepository+".git/info/refs" {
		return forwardedTransportEvidence{}, errors.New("C4 correlated forwarded transport row has unsafe or unexpected fields")
	}
	evidence.Version = "broker/c4-forwarded-transport/v1"
	return evidence, nil
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func sha256Digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "c4 bilateral broker bootstrap:", err)
	os.Exit(1)
}
