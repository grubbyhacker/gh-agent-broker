// Command correlation-validate is an offline integrity checker for the broker's
// run-to-PR correlation outbox store. It opens the store at a given path and
// runs the store's Validate pass — schema version, referential integrity,
// one event per correlation, known versions, bounded payloads, and payloads
// that agree with their correlation row. It never mutates state and is safe to
// run against a copy of a production store.
//
// It does NOT consume the outbox, deploy, or read production config; Signal
// Plane consumption lives elsewhere.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"gh-agent-broker/internal/correlation"
)

func main() {
	fs := flag.NewFlagSet("correlation-validate", flag.ExitOnError)
	path := fs.String("store", "", "absolute path to the correlation outbox sqlite store")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}
	if *path == "" {
		fatal(fmt.Errorf("-store is required"))
	}

	ctx := context.Background()
	store, err := correlation.Open(ctx, *path)
	if err != nil {
		fatal(err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "close store: %v\n", cerr)
		}
	}()

	if err := store.Validate(ctx); err != nil {
		fatal(err)
	}
	pending, err := store.PendingCount(ctx)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("ok: correlation store valid, %d event(s) awaiting consumption\n", pending)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
