package desync

// DefaultSafeStrategyDarwin is the macOS-safe ByeDPI argument set.
// --fake / --ttl are omitted: BSD rejects IP_TTL (byedpi#17).
// Runtime uses NativeSafeStrategy(); DefaultSafeStrategy() stays Windows.
//
// File is not named *_darwin.go so Windows CI can lock the invariant
// (this function must not replace DefaultSafeStrategy).
func DefaultSafeStrategyDarwin() Strategy {
	return Strategy{
		ID: "byedpi:darwin-safe",
		Args: []string{
			"--no-domain",
			"--timeout", "3",
			"--split", "1",
			"--disorder", "3+s",
			"--mod-http", "h,d",
			"--auto", "torst",
			"--tlsrec", "1+s",
		},
		Note: "Darwin-safe split/disorder/tlsrec; no fake/ttl (BSD IP_TTL)",
	}
}
