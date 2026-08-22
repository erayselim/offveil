package desync

// ScanCandidates is the limited blockcheck-style set.
// Ordered safest / most common first; scan stops at the first TLS OK.
//
// Sources (2025-2026):
//   - hufrea/byedpi dist/windows/byedpi.bat + README Windows notes
//   - ByeDPI --auto group patterns (torst / ssl_err)
//   - zapret blockcheck philosophy: try split/disorder/fake/ttl variants, stop early
//
// Not a full zapret force scan (minutes); budget is ScanDefaultTimeout.
func ScanCandidates() []Strategy {
	return []Strategy{
		DefaultSafeStrategy(),
		{
			ID: "byedpi:split-disorder",
			Args: []string{
				"--no-domain",
				"--timeout", "3",
				"--split", "1",
				"--disorder", "3+s",
				"--mod-http", "h,d",
			},
			Note: "Windows bat primary without --auto cascade",
		},
		{
			ID: "byedpi:split-sni",
			Args: []string{
				"--no-domain",
				"--timeout", "3",
				"--split", "1+s",
				"--disorder", "3+s",
			},
			Note: "SNI-offset split + disorder (README Windows)",
		},
		{
			ID: "byedpi:disorder-fake",
			Args: []string{
				"--no-domain",
				"--timeout", "3",
				"--disorder", "1",
				"--fake", "-1",
				"--ttl", "8",
			},
			Note: "Windows fake+disorder (README)",
		},
		{
			ID: "byedpi:disorder-fake-ttl5",
			Args: []string{
				"--no-domain",
				"--timeout", "3",
				"--disorder", "1",
				"--fake", "-1",
				"--ttl", "5",
			},
			Note: "Fake with lower TTL (ISP-sensitive)",
		},
		{
			ID: "byedpi:tlsrec-sni",
			Args: []string{
				"--no-domain",
				"--timeout", "3",
				"--tlsrec", "1+s",
			},
			Note: "TLS record split in SNI only",
		},
	}
}

// StrategyByID returns a named candidate or false.
func StrategyByID(id string) (Strategy, bool) {
	if id == "" {
		return Strategy{}, false
	}
	for _, s := range ScanCandidates() {
		if s.ID == id {
			return s, true
		}
	}
	if id == DefaultSafeStrategy().ID {
		return DefaultSafeStrategy(), true
	}
	return Strategy{}, false
}
