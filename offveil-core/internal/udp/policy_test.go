package udp_test

import (
	"github.com/erayselim/offveil/offveil-core/internal/udp"
	"testing"
)

func TestTransportPolicy(t *testing.T) {
	for _, tc := range []struct {
		in   string
		path udp.UDPPath
		quic udp.QuicPolicy
	}{
		{"tunnel", udp.PathTunnel, udp.QuicPass}, {"warp", udp.PathTunnel, udp.QuicPass}, {"reality", udp.PathTunnel, udp.QuicPass},
		{"desync", udp.PathDirect, udp.QuicPass}, {"DESYNC", udp.PathDirect, udp.QuicPass}, {"", udp.PathDirect, udp.QuicPass},
		{"direct", udp.PathDirect, udp.QuicPass},
	} {
		got := udp.ForOutbound(tc.in)
		if got.Path != tc.path || got.Quic != tc.quic || got.Note == "" {
			t.Errorf("%q: %+v", tc.in, got)
		}
	}
}

func TestQUICRejectIsProtocolOnly(t *testing.T) {
	rule := udp.QuicRejectRule()
	if rule["protocol"] != "quic" || rule["action"] != "reject" || len(rule) != 3 {
		t.Fatalf("non-generic QUIC rule: %v", rule)
	}
}
