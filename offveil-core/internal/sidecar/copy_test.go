package sidecar

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCopySignedReplaceAndSign(t *testing.T) {
	orig := runCodesign
	t.Cleanup(func() { runCodesign = orig })
	signed := ""
	runCodesign = func(path string) error {
		signed = path
		return nil
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "out", Names(ByeDPI)[0])
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CopySigned(src, dst); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "payload" {
		t.Fatalf("dst=%q", b)
	}
	if runtime.GOOS == "darwin" {
		if signed != dst {
			t.Fatalf("codesign path=%q want %q", signed, dst)
		}
	} else if signed != "" {
		t.Fatalf("non-darwin must not codesign, signed=%q", signed)
	}
}

func TestSignNoopOffDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin Sign calls codesign")
	}
	orig := runCodesign
	t.Cleanup(func() { runCodesign = orig })
	runCodesign = func(string) error {
		t.Fatal("codesign must not run")
		return nil
	}
	if err := Sign(filepath.Join(t.TempDir(), "x")); err != nil {
		t.Fatal(err)
	}
}
