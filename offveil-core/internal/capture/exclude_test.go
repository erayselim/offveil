package capture_test

import (
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
		netip.MustParsePrefix("162.159.128.233/32"), // discord-ish public
		netip.MustParsePrefix("8.8.8.8/32"),
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
		{"8.8.8.8", false},
		{"162.159.136.234", false},
	}
	for _, tc := range cases {
		got := capture.IsExcluded(netip.MustParseAddr(tc.addr), ex)
		if got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.addr, got, tc.want)
		}
	}
}
