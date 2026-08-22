package dns

import "testing"

func TestNRPTNamespaces(t *testing.T) {
	got := NRPTNamespaces([]string{"discord.com", ".discord.gg", "discord.com", "*.discord.media"})
	want := map[string]bool{
		"discord.com": true, ".discord.com": true,
		"discord.gg": true, ".discord.gg": true,
		"discord.media": true, ".discord.media": true,
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d got=%v", len(got), got)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("unexpected %q in %v", n, got)
		}
	}
}
