package dns

import "strings"

// NRPTCatchAll is the Windows NRPT "Any" namespace (dot notation).
// It steers every DNS Client query to GenericDNSServers (the local DoH stub).
const NRPTCatchAll = "."

// NRPTNamespaces turns domains into Windows NRPT namespace entries.
// Catch-all (".", "*", "any") is kept as ".". Other names emit apex plus
// leading-dot suffix (discord.com + .discord.com) so the registrable domain
// and its subdomains both match.
func NRPTNamespaces(domains []string) []string {
	seen := map[string]struct{}{}
	var out []string
	addNS := func(ns string) {
		if _, ok := seen[ns]; ok {
			return
		}
		seen[ns] = struct{}{}
		out = append(out, ns)
	}
	add := func(s string) {
		s = strings.TrimSpace(strings.ToLower(s))
		switch s {
		case ".", "*", "any", "any.":
			addNS(NRPTCatchAll)
			return
		}
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
		addNS(s)
		addNS("." + s)
	}
	for _, d := range domains {
		add(d)
	}
	return out
}
