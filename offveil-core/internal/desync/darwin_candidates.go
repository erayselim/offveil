package desync

// ScanCandidatesDarwin is the Darwin scan list: no --fake / --ttl.
// OOB is the extra fallback. Windows ScanCandidates() is unchanged.
//
// File is not named *_darwin.go so Windows tests can compile it.
func ScanCandidatesDarwin() []Strategy {
	return []Strategy{
		DefaultSafeStrategyDarwin(),
		{
			ID: "byedpi:split-disorder",
			Args: []string{
				"--no-domain",
				"--timeout", "3",
				"--split", "1",
				"--disorder", "3+s",
				"--mod-http", "h,d",
			},
			Note: "Primary without --auto cascade",
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
			ID: "byedpi:oob",
			Args: []string{
				"--no-domain",
				"--timeout", "3",
				"--oob", "1+s",
			},
			Note: "OOB fallback (Darwin scan; no fake/ttl)",
		},
	}
}
