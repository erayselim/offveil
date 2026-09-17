package sidecar

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Locate finds a sidecar next to offveil-core or under third_party/<vendor>.
func Locate(base string) (string, error) {
	names := Names(base)
	if len(names) == 0 {
		return "", fmt.Errorf("sidecar: empty name")
	}
	var candidates []string
	add := func(dir string) {
		if dir == "" {
			return
		}
		for _, n := range names {
			candidates = append(candidates, filepath.Join(dir, n))
		}
		vendor := vendorDir(base)
		for _, n := range names {
			candidates = append(candidates, filepath.Join(dir, "third_party", vendor, n))
		}
	}
	if exe, err := os.Executable(); err == nil {
		add(filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		add(wd)
		add(filepath.Join(wd, ".."))
	}
	vendor := vendorDir(base)
	for _, n := range names {
		candidates = append(candidates, filepath.Join("third_party", vendor, n))
	}

	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			abs, err := filepath.Abs(c)
			if err != nil {
				return c, nil
			}
			return abs, nil
		}
	}
	return "", fmt.Errorf("%s not found (%s)", names[0], locateHint())
}

// LocateInDir looks only in dir (setup copies from the installer tree).
func LocateInDir(dir, base string) (string, error) {
	for _, n := range Names(base) {
		p := filepath.Join(dir, n)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			abs, err := filepath.Abs(p)
			if err != nil {
				return p, nil
			}
			return abs, nil
		}
	}
	return "", fmt.Errorf("%s not in %s", base, dir)
}

func locateHint() string {
	if runtime.GOOS == "darwin" {
		return "run scripts/fetch-sing-box-darwin-arm64.sh and scripts/build-byedpi-darwin.sh"
	}
	return "run scripts/fetch-byedpi.ps1 / fetch-sing-box.ps1 and place next to offveil-core.exe"
}
