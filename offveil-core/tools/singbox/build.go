//go:build ignore

// Build the pinned upstream sidecar with offveil's reviewed dependency lock.
// This program uses only the standard library and never starts a tunnel.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const (
	version   = "1.13.14"
	toolchain = "go1.26.10"
	tags      = "with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api"
	module    = "github.com/sagernet/sing-box"
	sourceSum = "h1:p9/eqwilCgzyR/DpKM8hq7ppvzPIq1QMLgZWT3Cbg10="
)

func main() {
	if err := build(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: go run build.go <output-directory>")
	}
	if !((runtime.GOOS == "windows" && runtime.GOARCH == "amd64") || (runtime.GOOS == "darwin" && runtime.GOARCH == "arm64")) {
		return fmt.Errorf("unsupported sidecar host: %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	out, err := filepath.Abs(os.Args[1])
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return err
	}
	os.Setenv("GOTOOLCHAIN", toolchain)
	os.Setenv("CGO_ENABLED", "0")
	os.Setenv("GOOS", runtime.GOOS)
	os.Setenv("GOARCH", runtime.GOARCH)
	cmd := exec.Command("go", "mod", "download", "-json", module+"@v"+version)
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		return err
	}
	var src struct{ Dir, Zip, Sum string }
	if err := json.Unmarshal(data, &src); err != nil {
		return err
	}
	if src.Sum != sourceSum {
		return fmt.Errorf("sing-box source checksum mismatch: %s", src.Sum)
	}
	if err := run("mod", "verify"); err != nil {
		return err
	}
	if err := run("run", "golang.org/x/vuln/cmd/govulncheck@v1.1.4", "-tags", tags, module+"/cmd/sing-box"); err != nil {
		return err
	}
	name := "sing-box"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	stage, err := os.MkdirTemp(out, ".sing-box-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	binary := filepath.Join(stage, name)
	if err := run("build", "-mod=readonly", "-trimpath", "-tags", tags, "-ldflags", "-s -w -X "+module+"/constant.Version="+version, "-o", binary, module+"/cmd/sing-box"); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(src.Dir, "LICENSE"), filepath.Join(out, "LICENSE"), 0644); err != nil {
		return err
	}
	// Upstream's Go module archive omits the GPL text; keep the repository's
	// committed COPYING file alongside the original upstream license notice.
	if _, err := os.Stat(filepath.Join(out, "COPYING")); err != nil {
		return err
	}
	if err := copyFile(src.Zip, filepath.Join(out, "sing-box-"+version+"-source.zip"), 0644); err != nil {
		return err
	}
	return copyFile(binary, filepath.Join(out, name), 0755)
}

func run(args ...string) error {
	cmd := exec.Command("go", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode)
}
