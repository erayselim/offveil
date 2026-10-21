package sidecar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinFetchScriptsPinWindowsVersions(t *testing.T) {
	root := filepath.Join("..", "..", "scripts")
	winBox, err := os.ReadFile(filepath.Join(root, "fetch-sing-box.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	winDPI, err := os.ReadFile(filepath.Join(root, "fetch-byedpi.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	darBox, err := os.ReadFile(filepath.Join(root, "fetch-sing-box-darwin-arm64.sh"))
	if err != nil {
		t.Fatal(err)
	}
	darDPI, err := os.ReadFile(filepath.Join(root, "build-byedpi-darwin.sh"))
	if err != nil {
		t.Fatal(err)
	}
	sign, err := os.ReadFile(filepath.Join(root, "darwin-adhoc-sign.sh"))
	if err != nil {
		t.Fatal(err)
	}

	// Both native entry points share one source/dependency lock. This prevents
	// one platform silently returning to a prebuilt binary with an older Go.
	for _, script := range [][]byte{winBox, darBox} {
		if !strings.Contains(string(script), "go run build.go") || !strings.Contains(string(script), "tools/singbox") {
			t.Fatal("sing-box entry points must use the shared verified source build")
		}
		if strings.Contains(string(script), "releases/download") {
			t.Fatal("sing-box must not use an unpatched upstream binary")
		}
	}
	lock, err := os.ReadFile(filepath.Join("..", "..", "tools", "singbox", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lock), "require github.com/sagernet/sing-box v1.13.14") {
		t.Fatal("shared sing-box source version drifted")
	}

	if !strings.Contains(string(winDPI), `$Version = "0.17.3"`) {
		t.Fatal("windows byedpi version drifted")
	}
	if !strings.Contains(string(darDPI), `TAG="v0.17.3"`) {
		t.Fatal("darwin ByeDPI tag must match Windows 0.17.3")
	}
	if !strings.Contains(string(darDPI), "git clone") || !strings.Contains(string(darDPI), "make") {
		t.Fatal("ByeDPI darwin must git clone + make")
	}
	if strings.Contains(string(darDPI), "byedpi-17.3-aarch64.tar.gz") {
		t.Fatal("must not use Linux aarch64 ByeDPI tarball")
	}
	if !strings.Contains(string(darDPI), "7efde1b1296eaaa187b70e951894dde17527489c") {
		t.Fatal("ByeDPI commit pin missing")
	}

	if !strings.Contains(string(sign), "codesign --force -s -") {
		t.Fatal("ad-hoc codesign helper missing")
	}
}
