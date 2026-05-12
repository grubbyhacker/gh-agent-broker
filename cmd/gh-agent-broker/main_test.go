package main

import (
	"flag"
	"testing"
)

func TestCommonFlagsDoesNotExposeSecretAsDefault(t *testing.T) {
	t.Setenv("BROKER_AGENT_SECRET", "super-secret")
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_, _, secret := commonFlags(fs)
	if *secret != "" {
		t.Fatalf("secret flag default = %q, want empty", *secret)
	}
	resolveSecret(secret)
	if *secret != "super-secret" {
		t.Fatalf("resolved secret = %q", *secret)
	}
}
