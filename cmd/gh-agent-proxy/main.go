package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"gh-agent-broker/internal/proxy"
)

func main() {
	configPath := flag.String("config", "configs/proxy.example.yaml", "path to proxy YAML config")
	flag.Parse()

	cfg, err := proxy.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	service, err := proxy.NewService(cfg)
	if err != nil {
		log.Fatalf("init proxy: %v", err)
	}

	log.Printf("gh-agent-proxy listening on %s", cfg.Listen)
	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           service,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.Timeout.Duration + 10*time.Second,
		WriteTimeout:      cfg.Timeout.Duration + 10*time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
