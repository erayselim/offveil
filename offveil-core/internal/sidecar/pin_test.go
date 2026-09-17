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

	if !strings.Contains(string(winBox), `$Version = "1.13.14"`) {
		t.Fatal("windows sing-box version drifted")
	}
	if !strings.Contains(string(darBox), `VERSION="1.13.14"`) {
		t.Fatal("darwin sing-box must stay on 1.13.14")
	}
	if !strings.Contains(string(darBox), "darwin-arm64.tar.gz") {
		t.Fatal("darwin asset name")
	}
	if !strings.Contains(string(darBox), "73e8967b0fc08e17bce4263ca56ebc394822401a16497a1c4e02316c888202ab") {
		t.Fatal("darwin sing-box SHA pin missing")
	}
	if strings.Contains(string(darBox), "sing-box-${VERSION}-linux") {
		t.Fatal("must not fetch linux sing-box")
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
