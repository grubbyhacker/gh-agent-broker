package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"gh-agent-broker/internal/reporter"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	configPath := flag.String("config", "configs/reporter.example.yaml", "path to reporter YAML config")
	flag.Parse()

	cfg, err := reporter.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	service := reporter.NewService(cfg)
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "gh-agent-broker-issue-reporter", Version: "v1"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "broker_reporter_capabilities",
		Description: "Discover reporter repositories, labels, size limits, and dedupe requirements.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, reporter.CapabilitiesOutput, error) {
		out := service.Capabilities()
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "reporter capabilities returned"}},
		}, out, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "broker_report_issue",
		Description: "Create an allowlisted GitHub issue through gh-agent-broker using the reporter identity.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in reporter.ReportIssueInput) (*mcp.CallToolResult, reporter.ReportIssueOutput, error) {
		out, err := service.ReportIssue(in)
		if err != nil {
			return nil, reporter.ReportIssueOutput{}, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("created issue #%d: %s", out.Number, out.HTMLURL)}},
		}, out, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "broker_get_issue",
		Description: "Read one allowlisted GitHub issue through gh-agent-broker using the reporter identity.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in reporter.GetIssueInput) (*mcp.CallToolResult, reporterIssueOutput, error) {
		out, err := service.GetIssue(in)
		if err != nil {
			return nil, reporterIssueOutput{}, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("read issue #%d: %s", out.Number, out.HTMLURL)}},
		}, reporterIssueOutput{Issue: out}, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "broker_search_issues",
		Description: "Search allowlisted GitHub issues through gh-agent-broker using the reporter identity.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in reporter.SearchIssuesInput) (*mcp.CallToolResult, reporterIssuesOutput, error) {
		out, err := service.SearchIssues(in)
		if err != nil {
			return nil, reporterIssuesOutput{}, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("returned %d issues", len(out))}},
		}, reporterIssuesOutput{Issues: out}, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "broker_list_issue_comments",
		Description: "List comments on one allowlisted GitHub issue through gh-agent-broker using the reporter identity.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in reporter.ListIssueCommentsInput) (*mcp.CallToolResult, reporterIssueCommentsOutput, error) {
		out, err := service.ListIssueComments(in)
		if err != nil {
			return nil, reporterIssueCommentsOutput{}, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("returned %d issue comments", len(out))}},
		}, reporterIssueCommentsOutput{Comments: out}, nil
	})

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
	mux.Handle(cfg.MCPPath, mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return mcpServer
	}, &mcp.StreamableHTTPOptions{Stateless: true}))

	log.Printf("broker issue reporter listening on %s, mcp path %s", cfg.Listen, cfg.MCPPath)
	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type reporterIssueOutput struct {
	Issue interface{} `json:"issue"`
}

type reporterIssuesOutput struct {
	Issues interface{} `json:"issues"`
}

type reporterIssueCommentsOutput struct {
	Comments interface{} `json:"comments"`
}
