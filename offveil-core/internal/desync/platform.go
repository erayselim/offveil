package desync

import (
	"runtime"
	"strings"
)

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

// ContainsDarwinUnsupported also rejects cached disorder/disoob strategies:
// both call setttl() internally in ByeDPI v0.17.3.
func ContainsDarwinUnsupported(args []string) bool {
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		switch name {
		case "--fake", "--ttl", "--disorder", "--disoob":
			return true
		}
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 1 {
			switch arg[1] {
			case 'f', 't', 'd', 'q':
				return true
			}
		}
	}
	return false
}

// UsableOnOS rejects cached strategies that use BSD-incompatible operations.
func UsableOnOS(s Strategy) bool {
	if runtime.GOOS != "darwin" {
		return true
	}
	return !ContainsDarwinUnsupported(s.Args)
}
