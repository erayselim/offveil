package sidecar

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// runCodesign is codesign --force -s - (injected in tests).
var runCodesign = func(path string) error {
	cmd := exec.Command("codesign", "--force", "-s", "-", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign %s: %s (%w)", path, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Sign applies an ad-hoc signature on Darwin. No-op elsewhere.
func Sign(path string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	return runCodesign(path)
}

// CopySigned replace-copies src onto dst (new inode) and re-signs on Darwin.
// In-place cp keeps the inode; macOS then may kill the binary (Killed: 9).
func CopySigned(src, dst string) error {
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	if srcAbs == dstAbs {
		return Sign(dstAbs)
	}
	if err := copyReplace(srcAbs, dstAbs); err != nil {
		return err
	}
	return Sign(dstAbs)
}

func copyReplace(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".offveil-sidecar-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, copyErr := io.Copy(tmp, in)
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if copyErr != nil {
		_ = os.Remove(tmpName)
		return copyErr
	}
	if syncErr != nil {
		_ = os.Remove(tmpName)
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpName)
		return closeErr
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(dst)
		if err2 := os.Rename(tmpName, dst); err2 != nil {
			_ = os.Remove(tmpName)
			return err
		}
	}
	return nil
}
