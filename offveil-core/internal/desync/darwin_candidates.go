package desync

// ScanCandidatesDarwin excludes explicit and implicit TTL operations.
// OOB is the extra fallback. Windows ScanCandidates() is unchanged.
//
// File is not named *_darwin.go so Windows tests can compile it.
func ScanCandidatesDarwin() []Strategy {
	return []Strategy{
		DefaultSafeStrategyDarwin(),
		{
			ID: "byedpi:darwin-split-sni",
			Args: []string{
				"--no-domain",
				"--split", "1+s",
				"--mod-http", "h,d",
			},
			Note: "TCP split inside SNI, without TTL manipulation",
		},
		{
			ID: "byedpi:tlsrec-sni",
			Args: []string{
				"--no-domain",
				"--tlsrec", "1+s",
			},
			Note: "TLS record split in SNI only",
		},
		{
			ID: "byedpi:oob",
			Args: []string{
				"--no-domain",
				"--oob", "1+s",
			},
			Note: "OOB fallback (Darwin scan; no fake/ttl)",
		},
	}
}
