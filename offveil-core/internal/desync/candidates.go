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
		{
			ID:   "byedpi:split-sni-mid",
			Args: []string{"--no-domain", "--timeout", "3", "--split", "1", "--split", "0+sm"},
			Note: "TCP header and middle-of-SNI splits without TTL-dependent tricks",
		},
		{
			ID:   "byedpi:tlsrec-sni-mid",
			Args: []string{"--no-domain", "--timeout", "3", "--tlsrec", "0+sm"},
			Note: "TLS record boundary inside SNI, independent of TCP segmentation",
		},
		{
			ID:   "byedpi:split-tlsrec",
			Args: []string{"--no-domain", "--timeout", "3", "--split", "1", "--split", "1+s", "--tlsrec", "1+s"},
			Note: "Combine TCP and TLS record splits for different DPI reassembly paths",
		},
		{
			ID:   "byedpi:split-disorder-tlsrec",
			Args: []string{"--no-domain", "--timeout", "3", "--split", "1+s", "--disorder", "3+s", "--tlsrec", "1+s"},
			Note: "Windows split/disorder plus a separate TLS record boundary",
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
	for _, s := range ScanCandidatesDarwin() {
		if s.ID == id {
			return s, true
		}
	}
	if id == DefaultSafeStrategy().ID {
		return DefaultSafeStrategy(), true
	}
	if id == DefaultSafeStrategyDarwin().ID {
		return DefaultSafeStrategyDarwin(), true
	}
	return Strategy{}, false
}
