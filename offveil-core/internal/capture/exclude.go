package capture

import "net/netip"

// DefaultExcludePrefixes are never steered into the TUN (loop / LAN safety).
// Matches contracts.md §3.4 DIRECT zorunlulukları for private networks.
func DefaultExcludePrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),       // "this" network
		netip.MustParsePrefix("127.0.0.0/8"),     // localhost
		netip.MustParsePrefix("10.0.0.0/8"),      // RFC1918
		netip.MustParsePrefix("172.16.0.0/12"),   // RFC1918
		netip.MustParsePrefix("192.168.0.0/16"),  // RFC1918
		netip.MustParsePrefix("169.254.0.0/16"),  // link-local
		netip.MustParsePrefix("224.0.0.0/4"),     // multicast
		netip.MustParsePrefix("240.0.0.0/4"),     // reserved
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"),  // ULA
		netip.MustParsePrefix("fe80::/10"), // link-local
		netip.MustParsePrefix("ff00::/8"),  // multicast
	}
}

// IsExcluded reports whether addr falls in a default exclude prefix.
func IsExcluded(addr netip.Addr, excludes []netip.Prefix) bool {
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, p := range excludes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// FilterAllowlist drops excluded / invalid prefixes and rejects default routes.
// Selected-route only - never 0.0.0.0/0 or ::/0.
func FilterAllowlist(candidates []netip.Prefix, excludes []netip.Prefix) []netip.Prefix {
	if excludes == nil {
		excludes = DefaultExcludePrefixes()
	}
	out := make([]netip.Prefix, 0, len(candidates))
	seen := make(map[netip.Prefix]struct{}, len(candidates))
	for _, p := range candidates {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		if p.Bits() == 0 {
			continue // never install a full default-route
		}
		if IsExcluded(p.Addr(), excludes) {
			continue
		}
		// Also skip if the whole prefix is contained in an exclude.
		skip := false
		for _, ex := range excludes {
			if ex.Contains(p.Addr()) && ex.Bits() <= p.Bits() {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
