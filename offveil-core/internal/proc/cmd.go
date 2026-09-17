package proc

import "os/exec"

// PrepareCmd sets platform orphan-safety attributes before cmd.Start.
// Windows: no-op (Job Object is assigned after Start).
// Darwin: Setpgid so Close can SIGKILL the process group (ciadpi + grandchildren).
func PrepareCmd(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	prepareCmd(cmd)
}
