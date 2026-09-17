//go:build !windows && !darwin

package proc

import "os/exec"

func prepareCmd(*exec.Cmd) {}
