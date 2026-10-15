package sidecar

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCopySignedReplaceAndVerify(t *testing.T) {
	orig := runCodesign
	t.Cleanup(func() { runCodesign = orig })
	verified := ""
	runCodesign = func(path string) error {
		verified = path
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
		if filepath.Dir(verified) != filepath.Dir(dst) || verified == dst {
			t.Fatalf("must verify temporary copy before replacing dst, got %q", verified)
		}
	} else if verified != "" {
		t.Fatalf("non-darwin must not codesign, verified=%q", verified)
	}
}

func TestVerifySignatureNoopOffDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin VerifySignature calls codesign")
	}
	orig := runCodesign
	t.Cleanup(func() { runCodesign = orig })
	runCodesign = func(string) error {
		t.Fatal("codesign must not run")
		return nil
	}
	if err := VerifySignature(filepath.Join(t.TempDir(), "x")); err != nil {
		t.Fatal(err)
	}
}

func TestCopySignedInvalidSignaturePreservesInstallation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("signature verification is Darwin-only")
	}
	orig := runCodesign
	t.Cleanup(func() { runCodesign = orig })
	wantErr := errors.New("invalid signature")
	runCodesign = func(string) error { return wantErr }
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "new"), filepath.Join(dir, "installed")
	for path, data := range map[string]string{src: "damaged", dst: "working"} {
		if err := os.WriteFile(path, []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := CopySigned(src, dst); !errors.Is(err, wantErr) {
		t.Fatalf("err=%v want %v", err, wantErr)
	}
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "working" {
		t.Fatalf("installed binary changed: %q, %v", data, err)
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".offveil-sidecar-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary copies leaked: %v, %v", leftovers, err)
	}
}
