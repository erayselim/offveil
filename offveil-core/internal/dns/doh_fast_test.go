package dns

import (
	"context"
	"testing"
	"time"
)

func TestExchangeFailsFastWithBadEndpoints(t *testing.T) {
	c := NewDoHClient(DefaultPoisonSet())
	c.endpoints = []string{
		"https://127.0.0.1:1/dns-query",
		"https://127.0.0.1:2/dns-query",
	}
	start := time.Now()
	_, err := c.LookupA(context.Background(), "example.com")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error")
	}
	if elapsed > 6*time.Second {
		t.Fatalf("DoH should fail fast, took %v: %v", elapsed, err)
	}
	t.Logf("failed in %v: %v", elapsed, err)
}
