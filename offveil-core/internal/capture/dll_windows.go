//go:build windows

package capture

import (
	"fmt"
	"os"
	"path/filepath"
)

// LocateDLL finds the official side-by-side wintun.dll.
// Search order: OFFVEIL_WINTUN_DIR, exe dir, cwd, third_party/wintun.
func LocateDLL() (string, error) {
	candidates := []string{}
	if dir := os.Getenv("OFFVEIL_WINTUN_DIR"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, "wintun.dll"))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "wintun.dll"))
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "wintun.dll"),
			filepath.Join(cwd, "third_party", "wintun", "wintun.dll"),
		)
	}
	// When running from repo: offveil-core/third_party/wintun
	candidates = append(candidates, filepath.Join("third_party", "wintun", "wintun.dll"))

	var tried []string
	for _, p := range candidates {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		tried = append(tried, abs)
		if st, err := os.Stat(abs); err == nil && !st.IsDir() {
			return abs, nil
		}
	}
	return "", fmt.Errorf("wintun.dll not found (place official amd64 DLL next to offveil-core.exe); tried: %v", tried)
}

// ensureDLLBesideExe copies/links discovery path into the LoadLibrary search dir
// (APPLICATION_DIR) by setting the process DLL directory to the DLL's folder.
func ensureDLLLoadable(dllPath string) error {
	dir := filepath.Dir(dllPath)
	// Prefer copying beside exe so LoadLibraryEx(APPLICATION_DIR) succeeds
	// without SetDllDirectory side effects on the whole process.
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dest := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if filepath.Clean(dllPath) == filepath.Clean(dest) {
		return nil
	}
	in, err := os.ReadFile(dllPath)
	if err != nil {
		return err
	}
	// Only write if missing or different size - avoid clobbering a good copy.
	if st, err := os.Stat(dest); err != nil || st.Size() != int64(len(in)) {
		if err := os.WriteFile(dest, in, 0o644); err != nil {
			// Fallback: SetDllDirectory when we cannot write beside exe
			return setDLLDirectory(dir)
		}
	}
	_ = dir
	return nil
}
