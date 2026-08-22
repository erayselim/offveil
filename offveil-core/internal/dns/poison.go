package dns

import (
	"net/netip"
)

// Known Turkish censorship / filtering DNS reply fingerprints (OONI).
// Source: https://github.com/ooni/blocking-fingerprints fingerprints_dns.csv
// Primary: 195.175.254.2 - national poison reply since ~2014 (Discord block 2024+).
var defaultPoisonIPs = []string{
	"195.175.254.2",  // ooni.tr_6 cl.dns_nat_tr_poison
	"193.192.98.41",  // TurkNet family profile
	"193.192.98.42",  // TurkNet social media
	"193.192.98.43",  // TurkNet chat
	"193.192.98.45",  // TurkNet game
	"193.192.98.46",  // TurkNet chat+social
	"193.192.98.47",  // TurkNet game+social
	"193.192.98.48",  // TurkNet game+chat
	"193.192.98.49",  // TurkNet game+chat+social
}

// PoisonSet is a fast lookup of censorship fingerprint addresses.
type PoisonSet struct {
	ips map[netip.Addr]string // addr → fingerprint id
}

// DefaultPoisonSet returns the TR fingerprint set.
func DefaultPoisonSet() *PoisonSet {
	s := &PoisonSet{ips: make(map[netip.Addr]string, len(defaultPoisonIPs))}
	for _, raw := range defaultPoisonIPs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		id := "tr:" + raw
		if raw == "195.175.254.2" {
			id = "ooni.tr_6"
		}
		s.ips[addr] = id
	}
	return s
}

// Match reports whether addr is a known poison/censorship fingerprint.
func (s *PoisonSet) Match(addr netip.Addr) (id string, ok bool) {
	if s == nil {
		return "", false
	}
	id, ok = s.ips[addr]
	return id, ok
}

// MatchAny returns the first matching poison fingerprint among addrs.
func (s *PoisonSet) MatchAny(addrs []netip.Addr) (matched netip.Addr, id string, ok bool) {
	for _, a := range addrs {
		if id, hit := s.Match(a); hit {
			return a, id, true
		}
	}
	return netip.Addr{}, "", false
}

// ContainsPoison is true if any address is a known fingerprint.
func (s *PoisonSet) ContainsPoison(addrs []netip.Addr) bool {
	_, _, ok := s.MatchAny(addrs)
	return ok
}
