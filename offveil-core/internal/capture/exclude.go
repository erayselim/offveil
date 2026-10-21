package capture

import "net/netip"

// DefaultExcludePrefixes are never steered into the TUN (loop / LAN safety).
// Matches contracts.md §3.4 DIRECT (private / LAN).
func DefaultExcludePrefixes() []netip.Prefix {
	local := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),      // "this" network
		netip.MustParsePrefix("127.0.0.0/8"),    // localhost
		netip.MustParsePrefix("10.0.0.0/8"),     // RFC1918
		netip.MustParsePrefix("172.16.0.0/12"),  // RFC1918
		netip.MustParsePrefix("192.168.0.0/16"), // RFC1918
		netip.MustParsePrefix("169.254.0.0/16"), // link-local
		netip.MustParsePrefix("224.0.0.0/4"),    // multicast
		netip.MustParsePrefix("240.0.0.0/4"),    // reserved
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"),  // ULA
		netip.MustParsePrefix("fe80::/10"), // link-local
		netip.MustParsePrefix("ff00::/8"),  // multicast
	}
	return append(local, BootstrapExcludePrefixes()...)
}

// BootstrapExcludePrefixes keeps public resolver transport outside capture,
// including equivalent addresses on IPv6-only physical networks.
func BootstrapExcludePrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("1.1.1.1/32"),
		netip.MustParsePrefix("1.0.0.1/32"),
		netip.MustParsePrefix("8.8.8.8/32"),
		netip.MustParsePrefix("8.8.4.4/32"),
		netip.MustParsePrefix("9.9.9.9/32"),
		netip.MustParsePrefix("149.112.112.112/32"),
		netip.MustParsePrefix("2606:4700:4700::1111/128"),
		netip.MustParsePrefix("2606:4700:4700::1001/128"),
		netip.MustParsePrefix("2001:4860:4860::8888/128"),
		netip.MustParsePrefix("2001:4860:4860::8844/128"),
		netip.MustParsePrefix("2620:fe::fe/128"),
		netip.MustParsePrefix("2620:fe::9/128"),
	}
}

// IsExcluded reports whether addr falls in a default exclude prefix.
func IsExcluded(addr netip.Addr, excludes []netip.Prefix) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
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
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				continue
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Bits() == 0 {
			continue // never install a full default-route
		}
		if IsExcluded(p.Addr(), excludes) {
			continue
		}
		// A selected prefix must not capture an excluded address within it.
		skip := false
		for _, ex := range excludes {
			if ex.Overlaps(p) {
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
