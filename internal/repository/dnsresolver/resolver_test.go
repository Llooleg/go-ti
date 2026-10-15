package dnsresolver_test

import (
	"context"
	"testing"

	"go-ti/internal/repository/dnsresolver"
)

func TestLookupIPv4Literal(t *testing.T) {
	resolver := dnsresolver.New()

	ip, err := resolver.LookupIPv4(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("LookupIPv4() error = %v", err)
	}
	if got := ip.String(); got != "127.0.0.1" {
		t.Errorf("LookupIPv4() = %q, want %q", got, "127.0.0.1")
	}
}

func TestLookupIPv4NoResult(t *testing.T) {
	resolver := dnsresolver.New()

	_, err := resolver.LookupIPv4(context.Background(), "no-ip.invalid")
	if err == nil {
		t.Fatal("LookupIPv4() on unresolvable host: expected error")
	}
}
