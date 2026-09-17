package desync

import "runtime"

// NativeSafeStrategy is the OS default used at runtime.
// DefaultSafeStrategy() stays the Windows bat (tests lock fake/ttl).
func NativeSafeStrategy() Strategy {
	if runtime.GOOS == "darwin" {
		return DefaultSafeStrategyDarwin()
	}
	return DefaultSafeStrategy()
}

// NativeScanCandidates is the OS scan list used when ScanConfig.Candidates is empty.
// ScanCandidates() stays the Windows list (fake/ttl present).
func NativeScanCandidates() []Strategy {
	if runtime.GOOS == "darwin" {
		return ScanCandidatesDarwin()
	}
	return ScanCandidates()
}

// ContainsFakeOrTTL is true when argv would hit BSD-broken ByeDPI flags.
func ContainsFakeOrTTL(args []string) bool {
	for _, a := range args {
		if a == "--fake" || a == "--ttl" {
			return true
		}
	}
	return false
}

// UsableOnOS is false for a cached Windows fake/ttl strategy on Darwin.
func UsableOnOS(s Strategy) bool {
	if runtime.GOOS != "darwin" {
		return true
	}
	return !ContainsFakeOrTTL(s.Args)
}
