package sidecar

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLocateInDir(t *testing.T) {
	dir := t.TempDir()
	name := Names(ByeDPI)[0]
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := LocateInDir(dir, ByeDPI)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.Abs(path)
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if runtime.GOOS != "windows" {
		exe := filepath.Join(dir, "ciadpi.exe")
		if err := os.WriteFile(exe, []byte("win"), 0o755); err != nil {
			t.Fatal(err)
		}
		got, err = LocateInDir(dir, ByeDPI)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(got, ".exe") {
			t.Fatalf("darwin must ignore ciadpi.exe: %s", got)
		}
	}
}

func TestLocateInDirMissing(t *testing.T) {
	if _, err := LocateInDir(t.TempDir(), SingBox); err == nil {
		t.Fatal("expected missing")
	}
}
