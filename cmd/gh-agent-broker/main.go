package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"gh-agent-broker/internal/config"
)

type metadataFlag map[string]string

func (m *metadataFlag) String() string {
	return fmt.Sprintf("%v", map[string]string(*m))
}

func (m *metadataFlag) Set(v string) error {
	if *m == nil {
		*m = metadataFlag{}
	}
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return fmt.Errorf("metadata must be key=value")
	}
	(*m)[k] = val
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "health":
		cmdHealth(os.Args[2:])
	case "config-check":
		cmdConfigCheck(os.Args[2:])
	case "configure":
		cmdConfigure(os.Args[2:])
	case "probe":
		cmdProbe(os.Args[2:])
	case "dry-run":
		cmdDryRun(os.Args[2:])
	case "pr":
		cmdPR(os.Args[2:])
	case "comment":
		cmdComment(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gh-agent-broker-cli <health|config-check|configure|probe|dry-run|pr|comment> [flags]")
}

func commonFlags(fs *flag.FlagSet) (broker, agentID, secret *string) {
	broker = fs.String("broker", envDefault("BROKER_URL", "http://127.0.0.1:8080"), "broker base URL")
	agentID = fs.String("agent-id", os.Getenv("BROKER_AGENT_ID"), "broker agent ID")
	secret = fs.String("secret", "", "broker agent secret (defaults to BROKER_AGENT_SECRET)")
	return broker, agentID, secret
}

func cmdHealth(args []string) {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	broker := fs.String("broker", envDefault("BROKER_URL", "http://127.0.0.1:8080"), "broker base URL")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	resp, err := http.Get(strings.TrimRight(*broker, "/") + "/healthz")
	if err != nil {
		fatal(err)
	}
	defer closeBody(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatal(fmt.Errorf("health failed: %s", resp.Status))
	}
	fmt.Println("ok")
}

func cmdConfigCheck(args []string) {
	fs := flag.NewFlagSet("config-check", flag.ExitOnError)
	path := fs.String("config", "configs/example.yaml", "path to broker YAML config")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if _, err := config.Load(*path); err != nil {
		fatal(err)
	}
	fmt.Println("ok")
}

func cmdConfigure(args []string) {
	fs := flag.NewFlagSet("configure", flag.ExitOnError)
	broker := fs.String("broker", envDefault("BROKER_URL", "http://127.0.0.1:8080"), "broker base URL")
	repo := fs.String("repo", "", "owner/repo")
	remote := fs.String("remote", "origin", "git remote name")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *repo == "" {
		fatal(fmt.Errorf("-repo is required"))
	}
	if !validGitRemote(*remote) {
		fatal(fmt.Errorf("-remote contains invalid characters"))
	}
	url := strings.TrimRight(*broker, "/") + "/git/" + *repo + ".git"
	// #nosec G204 -- remote name is validated and URL is constructed by this CLI.
	cmd := exec.Command("git", "remote", "set-url", *remote, url)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatal(err)
	}
	fmt.Println(url)
}

func cmdProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	broker, agentID, secret := commonFlags(fs)
	repo := fs.String("repo", "", "owner/repo")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *repo == "" {
		fatal(fmt.Errorf("-repo is required"))
	}
	resolveSecret(secret)
	doRequest(http.MethodGet, *broker, "/v1/repos/"+*repo+"/probe", *agentID, *secret, nil)
}

func cmdDryRun(args []string) {
	fs := flag.NewFlagSet("dry-run", flag.ExitOnError)
	broker, agentID, secret := commonFlags(fs)
	repo := fs.String("repo", "", "owner/repo")
	operation := fs.String("operation", "", "operation name")
	branch := fs.String("branch", "", "branch/ref")
	base := fs.String("base", "", "base branch")
	var md metadataFlag
	fs.Var(&md, "metadata", "metadata key=value, repeatable")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	resolveSecret(secret)
	body := map[string]interface{}{"repo": *repo, "operation": *operation, "branch": *branch, "base_branch": *base, "metadata": map[string]string(md)}
	doRequest(http.MethodPost, *broker, "/v1/policy/dry-run", *agentID, *secret, body)
}

func cmdPR(args []string) {
	fs := flag.NewFlagSet("pr", flag.ExitOnError)
	broker, agentID, secret := commonFlags(fs)
	repo := fs.String("repo", "", "owner/repo")
	title := fs.String("title", "", "PR title")
	head := fs.String("head", "", "head branch")
	base := fs.String("base", "main", "base branch")
	bodyText := fs.String("body", "", "PR body")
	draft := fs.Bool("draft", false, "create draft PR")
	var md metadataFlag
	fs.Var(&md, "metadata", "metadata key=value, repeatable")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	resolveSecret(secret)
	body := map[string]interface{}{"title": *title, "head": *head, "base": *base, "body": *bodyText, "draft": *draft, "metadata": map[string]string(md)}
	doRequest(http.MethodPost, *broker, "/v1/repos/"+*repo+"/pulls", *agentID, *secret, body)
}

func cmdComment(args []string) {
	fs := flag.NewFlagSet("comment", flag.ExitOnError)
	broker, agentID, secret := commonFlags(fs)
	repo := fs.String("repo", "", "owner/repo")
	issue := fs.String("issue", "", "issue or PR number")
	bodyText := fs.String("body", "", "comment body")
	var md metadataFlag
	fs.Var(&md, "metadata", "metadata key=value, repeatable")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	resolveSecret(secret)
	body := map[string]interface{}{"body": *bodyText, "metadata": map[string]string(md)}
	doRequest(http.MethodPost, *broker, "/v1/repos/"+*repo+"/issues/"+*issue+"/comments", *agentID, *secret, body)
}

func doRequest(method, broker, path, agentID, secret string, body interface{}) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(broker, "/")+path, rdr)
	if err != nil {
		fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if agentID != "" || secret != "" {
		req.SetBasicAuth(agentID, secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal(err)
	}
	defer closeBody(resp.Body)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		fatal(err)
	}
	if resp.StatusCode >= 300 {
		fmt.Fprintln(os.Stderr, string(b))
		os.Exit(1)
	}
	fmt.Println(string(b))
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func resolveSecret(secret *string) {
	if *secret == "" {
		*secret = os.Getenv("BROKER_AGENT_SECRET")
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close response body: %v\n", err)
	}
}

func validGitRemote(remote string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9._-]+$`).MatchString(remote)
}
