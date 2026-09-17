// Package appdir is the per-machine data root for the privileged core.
// Env overrides (OFFVEIL_LOG_DIR, OFFVEIL_DIAG_DIR, …) stay in each caller.
package appdir

import (
	"os"
	"path/filepath"
	"runtime"
)

// Root is ProgramData/offveil on Windows, /Library/Application Support/offveil
// on Darwin (root daemon), and ~/.local/share/offveil elsewhere.
func Root() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "offveil")
	case "darwin":
		return filepath.Join("/Library/Application Support", "offveil")
	default:
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return filepath.Join(os.TempDir(), "offveil")
		}
		return filepath.Join(home, ".local", "share", "offveil")
	}
}
