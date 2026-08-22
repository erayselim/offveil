//go:build windows

package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
)

// ensureWintunBeside copies official wintun.dll next to sing-box.exe so the
// child process can CreateAdapter (Windows LoadLibrary searches the exe dir).
func ensureWintunBeside(singBoxPath string) error {
	if singBoxPath == "" {
		return fmt.Errorf("empty sing-box path")
	}
	dest := filepath.Join(filepath.Dir(singBoxPath), "wintun.dll")
	if st, err := os.Stat(dest); err == nil && !st.IsDir() && st.Size() > 0 {
		return nil
	}
	src, err := locateWintunDLL()
	if err != nil {
		return err
	}
	if filepath.Clean(src) == filepath.Clean(dest) {
		return nil
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, b, 0o644)
}

func locateWintunDLL() (string, error) {
	var candidates []string
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
	candidates = append(candidates, filepath.Join("third_party", "wintun", "wintun.dll"))
	for _, p := range candidates {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if st, err := os.Stat(abs); err == nil && !st.IsDir() {
			return abs, nil
		}
	}
	return "", fmt.Errorf("wintun.dll not found")
}
