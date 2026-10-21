// Package udp describes transport policy independently of applications or hosts.
package udp

import "strings"

type QuicPolicy string

const (
	QuicDrop QuicPolicy = "drop"
	QuicPass QuicPolicy = "pass"
)

type UDPPath string

const (
	PathDirect UDPPath = "direct"
	PathTunnel UDPPath = "tunnel"
)

// Info separates ordinary UDP transport from QUIC fallback policy. Local TLS
// desynchronization cannot protect opaque datagrams; they remain direct.
type Info struct {
	Path                 UDPPath    `json:"path"`
	Quic                 QuicPolicy `json:"quic"`
	Note                 string     `json:"note,omitempty"`
	QuicFallbackFamilies []string   `json:"quic_fallback_families,omitempty"`
}

func ForOutbound(path string) Info {
	switch strings.ToLower(strings.TrimSpace(path)) {
	case "tunnel", "warp", "reality", "remote":
		return Info{Path: PathTunnel, Quic: QuicPass, Note: "Public UDP and QUIC use the verified remote transport."}
	case "direct":
		return Info{Path: PathDirect, Quic: QuicPass, Note: "UDP and QUIC use the physical network."}
	default:
		return Info{Path: PathDirect, Quic: QuicDrop, QuicFallbackFamilies: []string{"ipv4"}, Note: "Local mode: opaque UDP and IPv6 stay direct; IPv4 QUIC falls back to TCP."}
	}
}

// QuicRejectRule matches the protocol, never a UDP port or application identity.
func QuicRejectRule() map[string]any {
	return map[string]any{"protocol": "quic", "action": "reject", "method": "drop"}
}
