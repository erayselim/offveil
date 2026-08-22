package dns_test

import (
	"context"
	"os"
	"testing"
	"time"

	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
)

func TestDoHLookupCloudflare(t *testing.T) {
	if os.Getenv("OFFVEIL_NET_TEST") == "" {
		t.Skip("set OFFVEIL_NET_TEST=1 for live DoH")
	}
	c := offdns.NewDoHClient(offdns.DefaultPoisonSet())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := c.LookupA(ctx, "cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) == 0 {
		t.Fatal("expected A records")
	}
	t.Logf("cloudflare.com → %v", addrs)
}
