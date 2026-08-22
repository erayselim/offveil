package dns

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPoisonMatchTR(t *testing.T) {
	s := DefaultPoisonSet()
	addr := netip.MustParseAddr("195.175.254.2")
	id, ok := s.Match(addr)
	if !ok || id != "ooni.tr_6" {
		t.Fatalf("expected ooni.tr_6, got ok=%v id=%q", ok, id)
	}
	clean := netip.MustParseAddr("1.1.1.1")
	if _, ok := s.Match(clean); ok {
		t.Fatal("1.1.1.1 should not be poison")
	}
}

func TestPoisonMatchAny(t *testing.T) {
	s := DefaultPoisonSet()
	addrs := []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("193.192.98.42"),
	}
	matched, id, ok := s.MatchAny(addrs)
	if !ok || matched.String() != "193.192.98.42" {
		t.Fatalf("got matched=%v id=%s ok=%v", matched, id, ok)
	}
}

func TestPoisonErrorClass(t *testing.T) {
	err := &PoisonError{
		Host:  "discord.com",
		Addr:  netip.MustParseAddr("195.175.254.2"),
		ID:    "ooni.tr_6",
		Via:   "system",
		Class: "dns_poison",
	}
	if err.Class != "dns_poison" {
		t.Fatal(err.Class)
	}
	if !strings.Contains(err.Error(), "dns_poison") {
		t.Fatal(err.Error())
	}
}
