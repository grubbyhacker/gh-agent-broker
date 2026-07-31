package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"gh-agent-broker/internal/codexrelay"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8093", "internal relay listen address")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("codex-subscription-relay listening on %s", *listen)
	if err := codexrelay.ListenAndServe(ctx, *listen, codexrelay.NewService(nil)); err != nil {
		log.Fatal(err)
	}
}
