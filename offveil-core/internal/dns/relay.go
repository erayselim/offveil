package dns

import "strings"

// Private Relay / Limit IP tracking override networksetup DNS. Core never
// disables them. Diag records the state; UI copy is a one-line hint.

const (
	PrivateRelayHintTR = "iCloud Özel Aktarma kapalı olsun."
	PrivateRelayHintEN = "Keep iCloud Private Relay off."
)

var privateRelayTokens = []string{
	"mask.icloud.com",
	"mask-h2.icloud.com",
	"mask-api.icloud.com",
	"doh.dns.apple.com",
}

// PrivateRelayFromScutil is true when scutil --dns shows Apple Private Relay.
func PrivateRelayFromScutil(out string) bool {
	s := strings.ToLower(out)
	for _, tok := range privateRelayTokens {
		if strings.Contains(s, tok) {
			return true
		}
	}
	return false
}

// RelayDiagNote is the PII-safe diagnostics line for a known probe result.
func RelayDiagNote(on bool) string {
	if on {
		return "icloud_private_relay: on — networksetup DNS is ignored; keep iCloud Private Relay and Limit IP tracking off. Core does not disable them."
	}
	return "icloud_private_relay: off"
}
