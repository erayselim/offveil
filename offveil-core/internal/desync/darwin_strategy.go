package desync

// DefaultSafeStrategyDarwin is the macOS-safe ByeDPI argument set.
// --disorder and --disoob also change TTL internally, even without --ttl.
// Keep Darwin on split/TLS-record/OOB operations (upstream byedpi#17).
// Runtime uses NativeSafeStrategy(); DefaultSafeStrategy() stays Windows.
//
// File is not named *_darwin.go so Windows CI can lock the invariant
// (this function must not replace DefaultSafeStrategy).
func DefaultSafeStrategyDarwin() Strategy {
	return Strategy{
		ID: "byedpi:darwin-safe",
		Args: []string{
			"--no-domain",
			"--split", "1",
			"--tlsrec", "1+s",
			"--mod-http", "h,d",
			"--auto", "torst",
			"--oob", "1+s",
		},
		Note: "Darwin split/tlsrec with OOB fallback; no explicit or implicit TTL manipulation",
	}
}
