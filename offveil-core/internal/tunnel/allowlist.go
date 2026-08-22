package tunnel

import "github.com/erayselim/offveil/offveil-core/internal/ruleset"

// DefaultTunnelDomains is the embedded selective allowlist (Discord).
// Prefer ruleset snapshot from engine; this is the embedded fallback.
func DefaultTunnelDomains() []string {
	return ruleset.MustLoadEmbedded().Doc.TunnelDomains()
}

// DefaultDirectDomains is the Steam / oyun seed that must stay DIRECT.
func DefaultDirectDomains() []string {
	return ruleset.MustLoadEmbedded().Doc.DirectDomains()
}

// IsDirectHost reports whether host (or a parent suffix) is on the DIRECT list.
func IsDirectHost(host string, list []string) bool {
	if host == "" {
		return false
	}
	if len(list) == 0 {
		list = DefaultDirectDomains()
	}
	h := normalizeHost(host)
	for _, d := range list {
		dd := normalizeHost(d)
		if h == dd || hasSuffixDot(h, dd) {
			return true
		}
	}
	return false
}

func normalizeHost(h string) string {
	for len(h) > 0 && (h[0] == '.' || h[0] == '*') {
		h = h[1:]
	}
	// lowercase ASCII
	b := make([]byte, len(h))
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func hasSuffixDot(host, suffix string) bool {
	if len(host) <= len(suffix) {
		return false
	}
	if host[len(host)-len(suffix):] != suffix {
		return false
	}
	return host[len(host)-len(suffix)-1] == '.'
}
