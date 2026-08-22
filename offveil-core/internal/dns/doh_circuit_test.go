package dns

import (
	"context"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestDoHCircuitOpensAfterFailures(t *testing.T) {
	c := NewDoHClient(DefaultPoisonSet())
	c.endpoints = []string{"https://127.0.0.1:1/dns-query"}

	msg := new(mdns.Msg)
	msg.SetQuestion("example.com.", mdns.TypeA)

	for i := 0; i < dohFailThreshold; i++ {
		_, _, err := c.Exchange(context.Background(), msg)
		if err == nil {
			t.Fatalf("iter %d: expected DoH failure", i)
		}
	}
	if c.Mode() != "plain_skip" {
		t.Fatalf("mode=%q want plain_skip", c.Mode())
	}

	start := time.Now()
	_, _, err := c.Exchange(context.Background(), msg)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected skip error")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("circuit skip should be instant, took %v", elapsed)
	}
}
