//go:build windows

package proc

import "os/exec"

func prepareCmd(*exec.Cmd) {}
