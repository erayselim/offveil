package proc

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
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
	exit     ExitInfo
}

type ExitInfo struct {
	At          string `json:"at"`
	Code        int    `json:"code"`
	Error       string `json:"error,omitempty"`
	StderrClass string `json:"stderr_class,omitempty"`
}

// WatchChild takes ownership of Wait for a successfully started command.
// Callers must not call cmd.Wait themselves after handing it off.
func WatchChild(cmd *exec.Cmd) *Child {
	c := &Child{cmd: cmd, done: make(chan struct{})}
	// A descendant retaining stderr must not hold teardown forever.
	cmd.WaitDelay = 2 * time.Second
	go func() {
		c.err = cmd.Wait()
		c.exit = ExitInfo{At: time.Now().UTC().Format(time.RFC3339), Code: -1}
		if cmd.ProcessState != nil {
			c.exit.Code = cmd.ProcessState.ExitCode()
		}
		if c.err != nil {
			c.exit.Error = c.err.Error()
		}
		if tail, ok := cmd.Stderr.(*TailBuffer); ok {
			c.exit.StderrClass = stderrClass(tail.String())
		}
		close(c.done)
	}()
	return c
}

// Exit publishes completed process facts without exporting arbitrary sidecar logs.
func (c *Child) Exit() *ExitInfo {
	if c == nil || c.Running() {
		return nil
	}
	info := c.exit
	return &info
}

func stderrClass(tail string) string {
	tail = strings.ToLower(tail)
	for _, match := range []struct{ text, class string }{
		{"too many open files", "file_limit"},
		{"cannot allocate memory", "memory_limit"},
		{"out of memory", "memory_limit"},
		{"address already in use", "address_in_use"},
		{"only one usage of each socket address", "address_in_use"},
		{"not enough buffer space", "socket_limit"},
		{"no buffer space available", "socket_limit"},
		{"permission denied", "permission_denied"},
		{"operation not permitted", "permission_denied"},
		{"access is denied", "permission_denied"},
		{"decode config", "config_invalid"},
		{"create tun", "tun_setup"},
		{"configure tun", "tun_setup"},
		{"open tun", "tun_setup"},
		{"create adapter", "tun_setup"},
		{"bind outbound interface", "interface_bind"},
		{"panic:", "panic"},
		{"fatal error:", "fatal"},
		{"fatal[", "fatal"},
		{"fatal ", "fatal"},
	} {
		if strings.Contains(tail, match.text) {
			return match.class
		}
	}
	if tail != "" {
		return "other"
	}
	return ""
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
