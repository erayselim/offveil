package dns

import "strings"

// NRPTNamespaces turns ruleset domains into Windows NRPT namespace entries.
// Apex (discord.com) plus leading-dot suffix (.discord.com) so both the
// registrable domain and its subdomains hit the local DoH stub.
func NRPTNamespaces(domains []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(strings.ToLower(s))
		s = strings.TrimSuffix(s, ".")
		for strings.HasPrefix(s, "*.") {
			s = strings.TrimPrefix(s, "*.")
		}
		for strings.HasPrefix(s, ".") {
			s = strings.TrimPrefix(s, ".")
		}
		if s == "" || strings.Contains(s, "/") {
			return
		}
		for _, ns := range []string{s, "." + s} {
			if _, ok := seen[ns]; ok {
				continue
			}
			seen[ns] = struct{}{}
			out = append(out, ns)
		}
	}
	for _, d := range domains {
		add(d)
	}
	return out
}
