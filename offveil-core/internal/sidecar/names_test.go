package sidecar

import (
	"runtime"
	"strings"
	"testing"
)

func TestNamesWindowsExeDarwinBare(t *testing.T) {
	for _, base := range []string{ByeDPI, SingBox, "ciadpi.exe"} {
		got := Names(base)
		if len(got) != 1 {
			t.Fatalf("base=%s names=%v", base, got)
		}
		if runtime.GOOS == "windows" {
			if !strings.HasSuffix(got[0], ".exe") {
				t.Fatalf("windows must search .exe, got %v", got)
			}
		} else {
			if strings.HasSuffix(got[0], ".exe") {
				t.Fatalf("darwin Locate must not search .exe, got %v", got)
			}
		}
	}
}

func TestVendorDir(t *testing.T) {
	if vendorDir(ByeDPI) != "byedpi" {
		t.Fatalf("ciadpi vendor=%s", vendorDir(ByeDPI))
	}
	if vendorDir(SingBox) != "sing-box" {
		t.Fatalf("sing-box vendor=%s", vendorDir(SingBox))
	}
}
