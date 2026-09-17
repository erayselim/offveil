//go:build darwin

package proc

import (
	"fmt"
	"os"
	"sync"
	"syscall"
)

// Job tracks Darwin process groups so closing the core reaps sidecar trees
// (ciadpi, sing-box, grandchildren). Windows Job Object equivalent.
type Job struct {
	mu     sync.Mutex
	pgids  map[int]struct{}
	closed bool
}

// NewKillOnCloseJob creates an empty process-group set.
func NewKillOnCloseJob() (*Job, error) {
	return &Job{pgids: map[int]struct{}{}}, nil
}

// Assign records the child's process group. Prefer PrepareCmd before Start
// so the child is already a group leader; Setpgid here is belt-and-suspenders.
func (j *Job) Assign(p *os.Process) error {
	if j == nil {
		return fmt.Errorf("job: nil")
	}
	if p == nil {
		return fmt.Errorf("job: nil process")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return fmt.Errorf("job: closed")
	}
	if err := syscall.Setpgid(p.Pid, 0); err != nil && err != syscall.EPERM && err != syscall.EACCES && err != syscall.ESRCH {
		return fmt.Errorf("Setpgid(%d): %w", p.Pid, err)
	}
	pgid, err := syscall.Getpgid(p.Pid)
	if err != nil {
		pgid = p.Pid
	}
	if pgid <= 0 {
		return fmt.Errorf("job: invalid pgid %d for pid %d", pgid, p.Pid)
	}
	j.pgids[pgid] = struct{}{}
	return nil
}

// Close SIGKILLs every tracked process group.
func (j *Job) Close() error {
	return j.signalAll(syscall.SIGKILL, true)
}

// Terminate sends SIGTERM to tracked groups without marking the job closed.
func (j *Job) Terminate(exitCode uint32) error {
	_ = exitCode
	return j.signalAll(syscall.SIGTERM, false)
}

func (j *Job) signalAll(sig syscall.Signal, close bool) error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if close {
		j.closed = true
	}
	var first error
	for pgid := range j.pgids {
		if err := syscall.Kill(-pgid, sig); err != nil && err != syscall.ESRCH {
			if first == nil {
				first = fmt.Errorf("kill(-%d): %w", pgid, err)
			}
		}
	}
	if close {
		j.pgids = map[int]struct{}{}
	}
	return first
}
