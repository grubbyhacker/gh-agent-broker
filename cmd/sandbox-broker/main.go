package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"gh-agent-broker/internal/sandbox"
	"gh-agent-broker/internal/server"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if command, args, ok := parseSubcommand(os.Args[1:]); ok {
		switch command {
		case "prune-runs":
			runPruneRuns(args)
		case "slim-runs":
			runSlimRuns(args)
		default:
			usage()
			os.Exit(2)
		}
		return
	}
	runServerCommand(os.Args[1:])
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sandbox-broker [server flags] | prune-runs [flags] | slim-runs [flags]")
	fmt.Fprintln(os.Stderr, "  slim-runs flags:")
	fmt.Fprintln(os.Stderr, "    -config <path>")
	fmt.Fprintln(os.Stderr, "    -docker-socket <path>")
	fmt.Fprintln(os.Stderr, "    -max-age <duration>")
	fmt.Fprintln(os.Stderr, "    -keep-newest <n>")
	fmt.Fprintln(os.Stderr, "    -terminal-only")
	fmt.Fprintln(os.Stderr, "    -max-bytes <bytes> (retained runs budget check before slimming)")
	fmt.Fprintln(os.Stderr, "    -dry-run")
	fmt.Fprintln(os.Stderr, "    -max-output <n>")
	fmt.Fprintln(os.Stderr, "  server flags: -config, -allow-public-bind, -docker-socket")
	fmt.Fprintln(os.Stderr, "  prune-runs flags:")
	fmt.Fprintln(os.Stderr, "    -config <path>")
	fmt.Fprintln(os.Stderr, "    -docker-socket <path>")
	fmt.Fprintln(os.Stderr, "    -max-age <duration>")
	fmt.Fprintln(os.Stderr, "    -keep-newest <n>")
	fmt.Fprintln(os.Stderr, "    -terminal-only")
	fmt.Fprintln(os.Stderr, "    -max-bytes <bytes>")
	fmt.Fprintln(os.Stderr, "    -dry-run")
	fmt.Fprintln(os.Stderr, "    -max-output <n>")
}

func runServerCommand(args []string) {
	fs := flag.NewFlagSet("sandbox-broker", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "configs/sandbox.example.yaml", "path to sandbox broker YAML config")
	allowPublicBind := fs.Bool("allow-public-bind", false, "allow binding to 0.0.0.0 or :PORT")
	dockerSocket := fs.String("docker-socket", "/var/run/docker.sock", "Docker Engine API socket")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("parse server flags: %v", err)
	}
	cfg, err := sandbox.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if !*allowPublicBind {
		if err := server.ValidateListenAddress(cfg.Listen); err != nil {
			log.Fatalf("invalid listen address: %v", err)
		}
	}
	auditLog, err := sandbox.NewAuditLogger(cfg.Audit.Path)
	if err != nil {
		log.Fatalf("open audit log: %v", err)
	}
	defer func() {
		if err := auditLog.Close(); err != nil {
			log.Printf("close audit log: %v", err)
		}
	}()
	intentStore, err := sandbox.OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
	if err != nil {
		log.Fatalf("open durable launch intent store: %v", err)
	}
	defer func() {
		if err := intentStore.Close(); err != nil {
			log.Printf("close durable launch intent store: %v", err)
		}
	}()
	service := sandbox.NewServiceWithLaunchIntents(cfg, sandbox.NewDockerBackend(*dockerSocket), auditLog, intentStore)
	if err := service.Reconcile(context.Background()); err != nil {
		log.Fatalf("reconcile runs: %v", err)
	}
	var authorityHandler http.Handler
	var authorityStore *sandbox.AuthorityWorkerStore
	if len(cfg.AuthorityProfiles) > 0 {
		authorityStore, err = sandbox.OpenAuthorityWorkerStore(context.Background(), cfg.AuthorityStore)
		if err != nil {
			log.Fatalf("open authority worker store: %v", err)
		}
		defer func() {
			if err := authorityStore.Close(); err != nil {
				log.Printf("close authority worker store: %v", err)
			}
		}()
		authorityService := sandbox.NewAuthorityWorkerService(cfg, authorityStore, sandbox.NewDockerAuthorityRuntime(*dockerSocket), auditLog).WithCheckpointStore(sandbox.NewCheckpointStore(cfg, authorityStore))
		authorityHandler = sandbox.NewAuthorityRESTHandler(authorityService)
	}

	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "gh-agent-sandbox-broker", Version: "v1"}, nil)
	registerTools(mcpServer, service)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"status":           "ok",
			"config_loaded_at": cfg.ConfigLoadedAt,
			"config_version":   cfg.ConfigVersion,
		}); err != nil {
			return
		}
	})
	mux.Handle(cfg.MCPPath, tokenAuth(cfg.AuthToken, mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return mcpServer
	}, &mcp.StreamableHTTPOptions{Stateless: true})))
	mux.Handle("/v1/", sandbox.NewRESTHandler(service))
	if authorityHandler != nil {
		mux.Handle("/v1/authority-workers", authorityHandler)
		mux.Handle("/v1/authority-workers/", authorityHandler)
	}

	log.Printf("sandbox broker listening on %s, mcp path %s", cfg.Listen, cfg.MCPPath)
	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Minute,
		WriteTimeout:      30 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type pruneCommand struct {
	ConfigPath   string
	DockerSocket string
	Policy       sandbox.RetentionPolicy
}

func parseSubcommand(args []string) (string, []string, bool) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, false
	}
	return args[0], args, true
}

func parsePruneCommand(args []string) (pruneCommand, error) {
	fs := flag.NewFlagSet("prune-runs", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cmd := pruneCommand{
		ConfigPath:   "configs/sandbox.example.yaml",
		DockerSocket: "/var/run/docker.sock",
		Policy: sandbox.RetentionPolicy{
			MaxAge:       24 * time.Hour,
			KeepNewest:   0,
			TerminalOnly: true,
			MaxBytes:     0,
			DryRun:       false,
			MaxOutput:    200,
		},
	}
	fs.StringVar(&cmd.ConfigPath, "config", cmd.ConfigPath, "path to sandbox broker YAML config")
	fs.StringVar(&cmd.DockerSocket, "docker-socket", cmd.DockerSocket, "Docker Engine API socket")
	fs.DurationVar(&cmd.Policy.MaxAge, "max-age", cmd.Policy.MaxAge, "maximum run age to keep before cleanup")
	fs.IntVar(&cmd.Policy.KeepNewest, "keep-newest", cmd.Policy.KeepNewest, "number of newest terminal runs to keep")
	fs.BoolVar(&cmd.Policy.TerminalOnly, "terminal-only", cmd.Policy.TerminalOnly, "only prune terminal-status runs")
	fs.Int64Var(&cmd.Policy.MaxBytes, "max-bytes", cmd.Policy.MaxBytes, "optional terminal run byte budget for retained run dirs")
	fs.BoolVar(&cmd.Policy.DryRun, "dry-run", cmd.Policy.DryRun, "log what would be pruned without deleting")
	fs.IntVar(&cmd.Policy.MaxOutput, "max-output", cmd.Policy.MaxOutput, "cap number of per-run entries in command output")
	if err := fs.Parse(args[1:]); err != nil {
		return pruneCommand{}, err
	}
	if cmd.Policy.MaxOutput < 1 {
		cmd.Policy.MaxOutput = 200
	}
	return cmd, nil
}

func parseSlimCommand(args []string) (pruneCommand, error) {
	return parsePruneCommand(args)
}

func runPruneRuns(args []string) {
	cmd, err := parsePruneCommand(args)
	if err != nil {
		log.Fatalf("invalid prune-runs arguments: %v", err)
	}

	cfg, err := sandbox.Load(cmd.ConfigPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	auditLog, err := sandbox.NewAuditLogger(cfg.Audit.Path)
	if err != nil {
		log.Fatalf("open audit log: %v", err)
	}
	defer func() {
		if err := auditLog.Close(); err != nil {
			log.Printf("close audit log: %v", err)
		}
	}()

	service := sandbox.NewService(cfg, sandbox.NewDockerBackend(cmd.DockerSocket), auditLog)
	report, err := service.PruneRuns(context.Background(), cmd.Policy)
	out, marshalErr := json.MarshalIndent(report, "", "  ")
	if marshalErr != nil {
		log.Fatalf("encode prune report: %v", marshalErr)
	}
	fmt.Println(string(out))
	if err != nil {
		log.Fatalf("prune failed: %v", err)
	}
}

func runSlimRuns(args []string) {
	cmd, err := parseSlimCommand(args)
	if err != nil {
		log.Fatalf("invalid slim-runs arguments: %v", err)
	}

	cfg, err := sandbox.Load(cmd.ConfigPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	auditLog, err := sandbox.NewAuditLogger(cfg.Audit.Path)
	if err != nil {
		log.Fatalf("open audit log: %v", err)
	}
	defer func() {
		if err := auditLog.Close(); err != nil {
			log.Printf("close audit log: %v", err)
		}
	}()

	service := sandbox.NewService(cfg, sandbox.NewDockerBackend(cmd.DockerSocket), auditLog)
	report, err := service.SlimRuns(context.Background(), cmd.Policy)
	out, marshalErr := json.MarshalIndent(report, "", "  ")
	if marshalErr != nil {
		log.Fatalf("encode slim report: %v", marshalErr)
	}
	fmt.Println(string(out))
	if err != nil {
		log.Fatalf("slim failed: %v", err)
	}
}

func registerTools(mcpServer *mcp.Server, service *sandbox.Service) {
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "launch_agent",
		Description: "Launch a task-scoped sandbox worker from an allowlisted template.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in sandbox.LaunchAgentInput) (*mcp.CallToolResult, sandbox.LaunchAgentOutput, error) {
		out, err := service.LaunchAgent(ctx, in)
		if err != nil {
			return nil, sandbox.LaunchAgentOutput{}, err
		}
		return textResult(fmt.Sprintf("launched %s on %s", out.RunID, out.Branch)), out, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "dry_run_launch",
		Description: "Validate a launch request without creating a run or container.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in sandbox.LaunchAgentInput) (*mcp.CallToolResult, sandbox.LaunchAgentOutput, error) {
		out, err := service.DryRunLaunch(ctx, in)
		if err != nil {
			return nil, sandbox.LaunchAgentOutput{}, err
		}
		return textResult(fmt.Sprintf("launch allowed; branch %s", out.Branch)), out, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "validate_template",
		Description: "Validate that a sandbox template exists and is usable.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in sandbox.ValidateTemplateInput) (*mcp.CallToolResult, sandbox.TemplateOutput, error) {
		out, err := service.ValidateTemplate(ctx, in)
		if err != nil {
			return nil, sandbox.TemplateOutput{}, err
		}
		return textResult("template valid"), out, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "list_agents",
		Description: "List known sandbox worker runs.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, sandbox.ListAgentsOutput, error) {
		out, err := service.ListAgents(ctx)
		if err != nil {
			return nil, sandbox.ListAgentsOutput{}, err
		}
		return textResult(fmt.Sprintf("%d runs", len(out.Runs))), out, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_agent_status",
		Description: "Return a sandbox worker run status.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in sandbox.RunInput) (*mcp.CallToolResult, sandbox.StatusOutput, error) {
		out, err := service.GetAgentStatus(ctx, in)
		if err != nil {
			return nil, sandbox.StatusOutput{}, err
		}
		return textResult(out.Status), out, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_agent_logs",
		Description: "Return byte-capped redacted sandbox worker logs.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in sandbox.LogsInput) (*mcp.CallToolResult, sandbox.LogsOutput, error) {
		out, err := service.GetAgentLogs(ctx, in)
		if err != nil {
			return nil, sandbox.LogsOutput{}, err
		}
		return textResult(out.Logs), out, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "stop_agent",
		Description: "Stop a running sandbox worker.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in sandbox.RunInput) (*mcp.CallToolResult, sandbox.StatusOutput, error) {
		out, err := service.StopAgent(ctx, in)
		if err != nil {
			return nil, sandbox.StatusOutput{}, err
		}
		return textResult(out.Status), out, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "collect_artifacts",
		Description: "Collect artifact manifest, hashes, and small redacted text snippets from /output.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in sandbox.RunInput) (*mcp.CallToolResult, sandbox.CollectionOutput, error) {
		out, err := service.CollectArtifacts(ctx, in)
		if err != nil {
			return nil, sandbox.CollectionOutput{}, err
		}
		return textResult(fmt.Sprintf("%d artifacts", len(out.Files))), out, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "collect_lessons",
		Description: "Collect lessons manifest, hashes, and small redacted text snippets from /lessons.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in sandbox.RunInput) (*mcp.CallToolResult, sandbox.CollectionOutput, error) {
		out, err := service.CollectLessons(ctx, in)
		if err != nil {
			return nil, sandbox.CollectionOutput{}, err
		}
		return textResult(fmt.Sprintf("%d lessons", len(out.Files))), out, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "cleanup_run",
		Description: "Explicitly remove a sandbox run directory and container.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in sandbox.RunInput) (*mcp.CallToolResult, sandbox.StatusOutput, error) {
		out, err := service.CleanupRun(ctx, in)
		if err != nil {
			return nil, sandbox.StatusOutput{}, err
		}
		return textResult(out.Status), out, nil
	})
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func tokenAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Sandbox-Token")
		if got == "" {
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
				got = strings.TrimSpace(auth[len("bearer "):])
			}
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			if _, err := w.Write([]byte(`{"error":"unauthorized"}` + "\n")); err != nil {
				return
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}
