package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"gh-agent-broker/internal/sandbox"
	"gh-agent-broker/internal/server"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	configPath := flag.String("config", "configs/sandbox.example.yaml", "path to sandbox broker YAML config")
	allowPublicBind := flag.Bool("allow-public-bind", false, "allow binding to 0.0.0.0 or :PORT")
	dockerSocket := flag.String("docker-socket", "/var/run/docker.sock", "Docker Engine API socket")
	flag.Parse()

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
	service := sandbox.NewService(cfg, sandbox.NewDockerBackend(*dockerSocket), auditLog)
	if err := service.Reconcile(context.Background()); err != nil {
		log.Fatalf("reconcile runs: %v", err)
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
		if _, err := w.Write([]byte(`{"status":"ok"}` + "\n")); err != nil {
			return
		}
	})
	mux.Handle(cfg.MCPPath, tokenAuth(cfg.AuthToken, mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return mcpServer
	}, &mcp.StreamableHTTPOptions{Stateless: true})))

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
