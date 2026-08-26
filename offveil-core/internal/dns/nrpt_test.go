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

func TestNRPTNamespacesCatchAll(t *testing.T) {
	for _, in := range [][]string{
		{"."},
		{"*"},
		{"any"},
		{"ANY."},
		{".", "discord.com"},
	} {
		got := NRPTNamespaces(in)
		if len(got) == 0 || got[0] != NRPTCatchAll {
			t.Fatalf("input %v: first=%v want %q first", in, got, NRPTCatchAll)
		}
		hasCatchAll := false
		for _, n := range got {
			if n == NRPTCatchAll {
				hasCatchAll = true
			}
			if n == "" {
				t.Fatalf("input %v: empty namespace in %v", in, got)
			}
		}
		if !hasCatchAll {
			t.Fatalf("input %v: missing catch-all in %v", in, got)
		}
	}

	// Bare catch-all must not be stripped to empty / dropped.
	got := NRPTNamespaces([]string{"."})
	if len(got) != 1 || got[0] != "." {
		t.Fatalf("bare catch-all=%v want [.]", got)
	}
}
