package capture

import (
	"strings"
	"unicode"
)

// IsVirtualDevice is true for tunnel / Apple virtual NICs that must not be
// treated as the physical egress (utun, ipsec, awdl, …).
func IsVirtualDevice(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if n == "lo" || (strings.HasPrefix(n, "lo") && len(n) > 2 && unicode.IsDigit(rune(n[2]))) {
		return true
	}
	for _, p := range []string{"utun", "ipsec", "ppp", "gif", "stf", "awdl", "llw", "bridge", "vmnet", "vboxnet", "zt"} {
		if n == p || strings.HasPrefix(n, p) {
			return true
		}
	}
	// ap0 / ap1 (Wi-Fi AP), not "apple".
	if strings.HasPrefix(n, "ap") && len(n) > 2 && unicode.IsDigit(rune(n[2])) {
		return true
	}
	return false
}
