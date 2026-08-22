//go:build windows

package proc

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Job wraps a Windows Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
// Closing the last handle terminates all assigned child processes (orphan safety).
type Job struct {
	handle windows.Handle
}

// NewKillOnCloseJob creates a job that kills members when the handle is closed.
func NewKillOnCloseJob() (*Job, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		h,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("SetInformationJobObject(KILL_ON_JOB_CLOSE): %w", err)
	}

	return &Job{handle: h}, nil
}

// Assign attaches an *os.Process to the job.
func (j *Job) Assign(p *os.Process) error {
	if j == nil || j.handle == 0 {
		return fmt.Errorf("job: nil handle")
	}
	if p == nil {
		return fmt.Errorf("job: nil process")
	}
	ph, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		uint32(p.Pid),
	)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", p.Pid, err)
	}
	defer windows.CloseHandle(ph)

	if err := windows.AssignProcessToJobObject(j.handle, ph); err != nil {
		return fmt.Errorf("AssignProcessToJobObject(%d): %w", p.Pid, err)
	}
	return nil
}

// Close closes the job handle. With KILL_ON_JOB_CLOSE, members are terminated.
func (j *Job) Close() error {
	if j == nil || j.handle == 0 {
		return nil
	}
	err := windows.CloseHandle(j.handle)
	j.handle = 0
	return err
}

// Terminate kills all processes currently in the job without closing the handle.
func (j *Job) Terminate(exitCode uint32) error {
	if j == nil || j.handle == 0 {
		return nil
	}
	return windows.TerminateJobObject(j.handle, exitCode)
}
