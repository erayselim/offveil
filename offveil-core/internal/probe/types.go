package probe

import (
	"net/netip"
	"time"
)

// Class values match docs/contracts.md §4.1.
type Class string

const (
	ClassOpen            Class = "open"
	ClassDNSPoison       Class = "dns_poison"
	ClassDPIReset        Class = "dpi_reset"
	ClassIPDrop          Class = "ip_drop"
	ClassTimeout         Class = "timeout"
	ClassThrottleSuspect Class = "throttle_suspect"
)

// Result is one curated-target probe outcome (contracts.md §4.2 / §4.3).
type Result struct {
	Target     string        `json:"target"`
	Class      Class         `json:"class"`
	Path       string        `json:"path"` // direct | desync | tunnel
	OK         bool          `json:"ok"`   // path expected to work for this class
	Detail     string        `json:"detail,omitempty"`
	Addrs      []netip.Addr  `json:"addrs,omitempty"`
	At         time.Time     `json:"at"`
	Took       time.Duration `json:"took,omitempty"`
	Confidence float64       `json:"confidence,omitempty"` // 0-1
}

// Report is the IPC test / session-start probe bundle (contracts.md §4.3).
type Report struct {
	ASN     string   `json:"asn"`
	ISPHint string   `json:"isp_hint,omitempty"`
	Results []Result `json:"results"`
	// Chosen is the cascade path for the session (worst of results).
	Chosen string `json:"chosen,omitempty"`
}

// PathFor maps probe class → outbound path (contracts.md §4.1).
func PathFor(c Class) string {
	switch c {
	case ClassOpen:
		return "direct"
	case ClassDNSPoison:
		// DoH already forced; treat residual as DPI until TLS says otherwise.
		return "desync"
	case ClassDPIReset:
		return "desync"
	case ClassIPDrop, ClassThrottleSuspect:
		return "tunnel"
	case ClassTimeout:
		// Belirsiz → desync first (engine may escalate to tunnel on desync fail).
		return "desync"
	default:
		return "desync"
	}
}

// pathRank ranks outbound severity for cascade aggregation (higher = more forced).
func pathRank(path string) int {
	switch path {
	case "tunnel":
		return 3
	case "desync":
		return 2
	case "direct":
		return 1
	default:
		return 0
	}
}

// PreferPath returns the more forced of two cascade paths.
func PreferPath(a, b string) string {
	if pathRank(b) > pathRank(a) {
		return b
	}
	return a
}
