package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"gh-agent-broker/internal/audit"
	"gh-agent-broker/internal/config"
	"gh-agent-broker/internal/githubapp"
	"gh-agent-broker/internal/server"
)

func main() {
	configPath := flag.String("config", "configs/example.yaml", "path to broker YAML config")
	allowPublicBind := flag.Bool("allow-public-bind", false, "allow binding to 0.0.0.0 or :PORT")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if !*allowPublicBind {
		if err := server.ValidateListenAddress(cfg.Server.Listen); err != nil {
			log.Fatalf("invalid listen address: %v", err)
		}
	}
	auditLog, err := audit.New(cfg.Audit.Path)
	if err != nil {
		log.Fatalf("open audit log: %v", err)
	}
	defer func() {
		if err := auditLog.Close(); err != nil {
			log.Printf("close audit log: %v", err)
		}
	}()
	gh, err := githubapp.New(cfg.GitHub)
	if err != nil {
		log.Fatalf("init github app client: %v", err)
	}
	srv := server.New(*configPath, cfg, gh, auditLog)
	srv.InstallSignalReload()
	log.Printf("gh-agent-broker listening on %s", cfg.Server.Listen)
	httpServer := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
