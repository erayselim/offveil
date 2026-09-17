package sidecar

import (
	"runtime"
	"strings"
)

const (
	// ByeDPI is the ciadpi binary base name (Windows adds .exe).
	ByeDPI = "ciadpi"
	// SingBox is the sing-box binary base name (Windows adds .exe).
	SingBox = "sing-box"
)

// Names is the Locate search list for a sidecar base name.
// Darwin: extensionless only. Windows: `.exe` only.
func Names(base string) []string {
	base = strings.TrimSuffix(strings.TrimSpace(base), ".exe")
	if base == "" {
		return nil
	}
	if runtime.GOOS == "windows" {
		return []string{base + ".exe"}
	}
	return []string{base}
}

func vendorDir(base string) string {
	switch strings.TrimSuffix(base, ".exe") {
	case ByeDPI:
		return "byedpi"
	case SingBox:
		return "sing-box"
	default:
		return base
	}
}
