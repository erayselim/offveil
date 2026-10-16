//go:build windows

package capture

import (
	"net/netip"
	"testing"
)

func TestWindowsSplitDefaultDoesNotExpandHostRoutes(t *testing.T) {
	s := &session{skipAdapter: true, splitDefault: true}
	if NeedsPrefixExpansion(s) {
		t.Fatal("split-default session requests prefix expansion")
	}
	if n, err := s.AddPrefixes([]netip.Prefix{netip.MustParsePrefix("203.0.113.10/32")}); n != 0 || err != nil {
		t.Fatalf("unused host routes attempted: %d %v", n, err)
	}
	if !NeedsPrefixExpansion(&session{skipAdapter: true}) {
		t.Fatal("per-host session no longer requests expansion")
	}
}
