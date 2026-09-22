// Command capability-store-validate is an offline integrity checker for the
// broker's durable capability store. It opens the store at a given path and runs
// the store's Validate pass — schema version, coherent claims per row, and
// reservations within budget. It never mutates state and never touches a handle
// (only stored SHA-256 hashes exist). Safe to run against a copy.
//
// It does NOT verify or reserve, deploy, or read production config.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"gh-agent-broker/internal/capability"
)

func main() {
	fs := flag.NewFlagSet("capability-store-validate", flag.ExitOnError)
	path := fs.String("store", "", "absolute path to the capability sqlite store")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}
	if *path == "" {
		fatal(fmt.Errorf("-store is required"))
	}
	ctx := context.Background()
	store, err := capability.OpenStore(ctx, *path)
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
	fmt.Println("ok: capability store valid")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
