// Package udp covers Discord voice media UDP and QUIC (UDP/443).
// Voice signalling is TCP/WSS; media is a separate UDP path that needs
// TUN or SOCKS5 UDP ASSOCIATE. QUIC is dropped so HTTPS falls back to TCP TLS.
package udp

import "strings"

// QuicPolicy is how UDP/443 (HTTP/3) is handled.
type QuicPolicy string

const (
	// QuicDrop rejects UDP/443 so clients fall back to TCP TLS (desync/tunnel-safe).
	QuicDrop QuicPolicy = "drop"
)

// VoiceUDPPath is which outbound carries Discord voice media UDP.
// Signalling (WSS) always follows the session TCP cascade path; media UDP
// mirrors that outbound so NAT binding stays consistent.
type VoiceUDPPath string

const (
	VoiceDirect VoiceUDPPath = "direct"
	VoiceDesync VoiceUDPPath = "desync" // ByeDPI SOCKS5 UDP ASSOCIATE
	VoiceTunnel VoiceUDPPath = "tunnel" // sing-box SOCKS → selective WG/Reality
)

// Info is diagnostics for status.udp (UI may ignore).
type Info struct {
	VoicePath VoiceUDPPath `json:"voice_path"`
	Quic      QuicPolicy   `json:"quic"`
	Note      string       `json:"note,omitempty"`
}

// ForOutbound maps the session TCP cascade path to voice UDP + QUIC policy.
//
//	direct → voice UDP direct; QUIC drop
//	desync → voice UDP via ByeDPI UDP ASSOCIATE (never --no-udp); QUIC drop
//	tunnel → voice UDP via sing-box SOCKS UDP → tunnel; QUIC drop
func ForOutbound(tcpPath string) Info {
	path := strings.ToLower(strings.TrimSpace(tcpPath))
	switch path {
	case "desync":
		return Info{
			VoicePath: VoiceDesync,
			Quic:      QuicDrop,
			Note:      "voice UDP → ByeDPI SOCKS5 UDP ASSOCIATE; QUIC/443 drop → TCP TLS",
		}
	case "tunnel":
		return Info{
			VoicePath: VoiceTunnel,
			Quic:      QuicDrop,
			Note:      "voice UDP → sing-box SOCKS → selective tunnel; QUIC/443 drop → TCP TLS",
		}
	case "direct":
		return Info{
			VoicePath: VoiceDirect,
			Quic:      QuicDrop,
			Note:      "voice UDP direct; QUIC/443 drop (force TCP HTTPS)",
		}
	default:
		return Info{
			VoicePath: VoiceDirect,
			Quic:      QuicDrop,
			Note:      "outbound unknown - voice UDP direct; QUIC/443 drop",
		}
	}
}

// IsVoiceHost reports Discord RTC / stream hostnames (voice + media signalling).
// Dynamic regional hosts are typically under .discord.gg or .discord.media.
func IsVoiceHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return false
	}
	if h == "discord.gg" || h == "discord.media" || h == "latency.discord.media" {
		return true
	}
	return strings.HasSuffix(h, ".discord.gg") || strings.HasSuffix(h, ".discord.media")
}

// QuicRejectRule is a sing-box route rule fragment: reject UDP/443 (QUIC).
// Place early in route.rules (before domain tunnel rules).
func QuicRejectRule() map[string]any {
	return map[string]any{
		"network": "udp",
		"port":    443,
		"action":  "reject",
		"method":  "drop",
	}
}
