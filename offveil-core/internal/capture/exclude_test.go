package capture_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
)

func TestFilterAllowlistRejectsDefaultAndLAN(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("192.168.1.1/32"),
		netip.MustParsePrefix("10.0.0.5/32"),
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("162.159.128.233/32"),
		netip.MustParsePrefix("8.8.8.8/32"),
		netip.MustParsePrefix("2606:2800:220::1/128"),
		netip.MustParsePrefix("2606:4700:4700::1111/128"),
		netip.MustParsePrefix("fd87:6f66:7665::1/128"),
		netip.MustParsePrefix("fe80::1/128"),
	}
	out := capture.FilterAllowlist(in, nil)
	if len(out) != 2 {
		t.Fatalf("want 2 public prefixes, got %v", out)
	}
	for _, p := range out {
		if p.Bits() == 0 {
			t.Fatalf("default route leaked: %v", p)
		}
		if capture.IsExcluded(p.Addr(), capture.DefaultExcludePrefixes()) {
			t.Fatalf("excluded addr leaked: %v", p)
		}
	}
}

func TestIsExcluded(t *testing.T) {
	ex := capture.DefaultExcludePrefixes()
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.1.2.3", true},
		{"192.168.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},
		{"2001:4860:4860::8888", true},
		{"2620:fe::fe", true},
		{"2606:2800:220::1", false},
		{"::ffff:8.8.8.8", true},
		{"::ffff:127.0.0.1", true},
		{"162.159.136.234", false},
	}
	for _, tc := range cases {
		got := capture.IsExcluded(netip.MustParseAddr(tc.addr), ex)
		if got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.addr, got, tc.want)
		}
	}
}

func TestSelectedPrefixCannotCaptureBootstrapWithinItsRange(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("1.1.0.0/16"),
		netip.MustParsePrefix("2001:4860:4860::/48"),
		netip.MustParsePrefix("::ffff:8.8.8.8/128"),
		netip.MustParsePrefix("::ffff:162.159.128.233/128"),
	}
	out := capture.FilterAllowlist(in, nil)
	if len(out) != 1 || out[0] != netip.MustParsePrefix("162.159.128.233/32") {
		t.Fatalf("bootstrap transport could reenter capture: %v", out)
	}
}

func TestResolvedDualStackDestinationsCannotCaptureBootstrap(t *testing.T) {
	cfg := capture.DefaultConfig()
	cfg.ResolveHosts = []string{"requested.example.test"}
	cfg.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("162.159.128.233"),
			netip.MustParseAddr("::ffff:162.159.128.233"),
			netip.MustParseAddr("2606:2800:220::1"),
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("2606:4700:4700::1111"),
			netip.MustParseAddr("fd87:6f66:7665::1"),
		}, nil
	}
	prefixes, err := capture.BuildAllowlist(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("bootstrap, local or mapped duplicate entered capture: %v", prefixes)
	}
	seen := map[netip.Prefix]bool{}
	for _, prefix := range prefixes {
		seen[prefix] = true
	}
	if !seen[netip.MustParsePrefix("162.159.128.233/32")] || !seen[netip.MustParsePrefix("2606:2800:220::1/128")] {
		t.Fatalf("public address family missing: %v", prefixes)
	}
}
