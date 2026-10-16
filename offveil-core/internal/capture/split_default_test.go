package capture

import (
	"context"
	"net/netip"
	"testing"
)

func TestSplitDefaultSkipsUnusedSeedResolution(t *testing.T) {
	for _, split := range []bool{true, false} {
		cfg := DefaultConfig()
		cfg.SkipAdapter, cfg.SplitDefault = true, split
		cfg.ResolveHosts = []string{"seed.test"}
		calls := 0
		cfg.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			calls++
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		}
		prefixes, err := BuildAllowlist(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if split && (calls != 0 || len(prefixes) != 0) {
			t.Fatal("split-default capture resolved unused host routes")
		}
		if !split && (calls != 1 || len(prefixes) != 1) {
			t.Fatal("per-host capture lost seed resolution")
		}
	}
}
