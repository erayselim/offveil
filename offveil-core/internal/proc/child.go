package proc

import (
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"
)

// Child owns the single Wait call for a started command. Exit state is
// published through done; Close can safely race with natural process exit.
type Child struct {
	cmd      *exec.Cmd
	done     chan struct{}
	err      error
	stopOnce sync.Once
}

// WatchChild takes ownership of Wait for a successfully started command.
// Callers must not call cmd.Wait themselves after handing it off.
func WatchChild(cmd *exec.Cmd) *Child {
	c := &Child{cmd: cmd, done: make(chan struct{})}
	// A descendant retaining stderr must not hold teardown forever.
	cmd.WaitDelay = 2 * time.Second
	go func() {
		c.err = cmd.Wait()
		close(c.done)
	}()
	return c
}

func (c *Child) Running() bool {
	if c == nil {
		return false
	}
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

func (c *Child) PID() int {
	if c == nil {
		return 0
	}
	return c.cmd.Process.Pid
}

func (c *Child) Close() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		if c.Running() {
			_ = c.cmd.Process.Kill()
		}
	})
	<-c.done
}

// WaitTCP preserves the startup budget while detecting an exited child early.
// Passing nil is useful for standalone SOCKS readiness tests.
func WaitTCP(addr string, timeout time.Duration, child *Child) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if child != nil && !child.Running() {
			return fmt.Errorf("process exited: %v", child.err)
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			if child != nil && !child.Running() {
				return fmt.Errorf("process exited: %v", child.err)
			}
			return nil
		}
		last = err
		timer := time.NewTimer(50 * time.Millisecond)
		if child == nil {
			<-timer.C
			continue
		}
		select {
		case <-child.done:
			timer.Stop()
			return fmt.Errorf("process exited: %v", child.err)
		case <-timer.C:
		}
	}
	if last == nil {
		last = fmt.Errorf("timeout")
	}
	return last
}
