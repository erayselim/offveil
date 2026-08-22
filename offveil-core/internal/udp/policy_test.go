package udp_test

import (
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/udp"
)

func TestForOutbound(t *testing.T) {
	cases := []struct {
		in    string
		voice udp.VoiceUDPPath
	}{
		{"direct", udp.VoiceDirect},
		{"desync", udp.VoiceDesync},
		{"tunnel", udp.VoiceTunnel},
		{"DESYNC", udp.VoiceDesync},
		{"", udp.VoiceDirect},
		{"none", udp.VoiceDirect},
	}
	for _, tc := range cases {
		got := udp.ForOutbound(tc.in)
		if got.VoicePath != tc.voice {
			t.Fatalf("%q: voice=%s want %s", tc.in, got.VoicePath, tc.voice)
		}
		if got.Quic != udp.QuicDrop {
			t.Fatalf("%q: quic=%s want drop", tc.in, got.Quic)
		}
		if got.Note == "" {
			t.Fatalf("%q: empty note", tc.in)
		}
	}
}

func TestIsVoiceHost(t *testing.T) {
	yes := []string{
		"us-central123.discord.gg",
		"c-ord12-0249fb78.discord.media",
		"latency.discord.media",
		"discord.gg",
		"DISCORD.MEDIA",
	}
	for _, h := range yes {
		if !udp.IsVoiceHost(h) {
			t.Fatalf("want voice host %q", h)
		}
	}
	no := []string{"discord.com", "cdn.discordapp.com", "imvu.com", "", "gg.discord.evil"}
	for _, h := range no {
		if udp.IsVoiceHost(h) {
			t.Fatalf("not voice host %q", h)
		}
	}
}

func TestQuicRejectRule(t *testing.T) {
	r := udp.QuicRejectRule()
	if r["network"] != "udp" || r["port"] != 443 {
		t.Fatalf("%v", r)
	}
	if r["action"] != "reject" {
		t.Fatalf("action=%v", r["action"])
	}
}
