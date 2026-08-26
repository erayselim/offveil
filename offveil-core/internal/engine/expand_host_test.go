package engine

import "testing"

func TestNormalizeExpandHost(t *testing.T) {
	okCases := []string{"discord.com", "cdn.discordapp.com", "YOUTUBE.COM."}
	for _, h := range okCases {
		got, ok := normalizeExpandHost(h)
		if !ok || got == "" {
			t.Fatalf("%q: ok=%v got=%q", h, ok, got)
		}
	}
	skip := []string{"", ".", ".local", "printer.local", "1.2.3.4.in-addr.arpa", "  "}
	for _, h := range skip {
		if _, ok := normalizeExpandHost(h); ok {
			t.Fatalf("%q should skip expand", h)
		}
	}
}
