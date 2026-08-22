package capture_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
)

func TestFakeSessionAddPrefixes(t *testing.T) {
	f := capture.NewFakeSession(capture.Info{
		RoutePrefixes: []string{"1.2.3.4/32"},
		RoutesApplied: 1,
	})
	p1 := netip.MustParsePrefix("1.2.3.4/32")
	p2 := netip.MustParsePrefix("5.6.7.8/32")
	n, err := f.AddPrefixes([]netip.Prefix{p1, p2})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("added=%d want 1 (skip duplicate)", n)
	}
	info := f.Info()
	if info.RoutesApplied != 2 {
		t.Fatalf("routes=%d", info.RoutesApplied)
	}
}

func TestBuildAllowlistIMVUSeeds(t *testing.T) {
	cfg := capture.Config{
		ResolveHosts: []string{"secure.imvu.com", "webasset-akm.imvu.com"},
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			switch host {
			case "secure.imvu.com":
				return []netip.Addr{netip.MustParseAddr("204.225.145.94")}, nil
			case "webasset-akm.imvu.com":
				return []netip.Addr{netip.MustParseAddr("172.64.155.127")}, nil
			default:
				return nil, nil
			}
		},
	}
	allow, err := capture.BuildAllowlist(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(allow) < 2 {
		t.Fatalf("allowlist len=%d want >=2 (IMVU login + CDN)", len(allow))
	}
	seen := map[string]bool{}
	for _, p := range allow {
		seen[p.Addr().String()] = true
	}
	if !seen["204.225.145.94"] || !seen["172.64.155.127"] {
		t.Fatalf("missing IMVU IPs: %v", allow)
	}
}
