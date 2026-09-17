//go:build darwin

package proc

import (
	"os/exec"
	"testing"
	"time"
)

func TestKillOnCloseProcessGroup(t *testing.T) {
	job, err := NewKillOnCloseJob()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sleep", "60")
	PrepareCmd(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := job.Assign(cmd.Process); err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	if err := job.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("child still alive after job close")
	}
}

func TestAssignNilAndClosed(t *testing.T) {
	job, err := NewKillOnCloseJob()
	if err != nil {
		t.Fatal(err)
	}
	if err := job.Assign(nil); err == nil {
		t.Fatal("expected error for nil process")
	}
	if err := job.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sleep", "5")
	PrepareCmd(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	if err := job.Assign(cmd.Process); err == nil {
		t.Fatal("expected error on closed job")
	}
}
