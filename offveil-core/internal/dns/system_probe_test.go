package dns

import (
	"context"
	"errors"
	"testing"
)

func TestProbeSystemDNSHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := ProbeSystemDNS(ctx, "offveil-probe.invalid", DefaultPoisonSet())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lookup did not honor cancellation: %v", err)
	}
}
