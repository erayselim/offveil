//go:build !windows

package proc

import (
	"fmt"
	"os"
)

// Job is a no-op stub on non-Windows builds.
type Job struct{}

func NewKillOnCloseJob() (*Job, error) {
	return &Job{}, nil
}

func (j *Job) Assign(p *os.Process) error {
	return fmt.Errorf("job objects are Windows-only")
}

func (j *Job) Close() error { return nil }

func (j *Job) Terminate(exitCode uint32) error { return nil }
