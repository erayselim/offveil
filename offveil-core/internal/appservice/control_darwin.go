//go:build darwin

package appservice

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const launchdTarget = "system/" + Name

func launchctl(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/launchctl", args...).CombinedOutput()
	if ctx.Err() != nil {
		return "", fmt.Errorf("launchctl %s timed out", args[0])
	}
	return strings.TrimSpace(string(out)), err
}

func daemonLoaded() (bool, int, error) {
	out, err := launchctl(5*time.Second, "print", launchdTarget)
	if err == nil {
		pid := 0
		for _, line := range strings.Split(out, "\n") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line), "pid = "); ok {
				pid, _ = strconv.Atoi(strings.TrimSpace(value))
				break
			}
		}
		return true, pid, nil
	}
	low := strings.ToLower(out)
	if strings.Contains(low, "could not find service") || strings.Contains(low, "no such process") || strings.Contains(low, "service not found") {
		return false, 0, nil
	}
	return false, 0, fmt.Errorf("launchctl print: %s (%w)", out, err)
}

// StartLaunchDaemon always operates in the system domain, independent of the
// caller's login session. bootstrap/kickstart replace legacy load/start.
func StartLaunchDaemon() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("system daemon start requires root")
	}
	loaded, _, err := daemonLoaded()
	if err != nil {
		return err
	}
	if out, err := launchctl(5*time.Second, "enable", launchdTarget); err != nil {
		return fmt.Errorf("launchctl enable: %s (%w)", out, err)
	}
	if !loaded {
		if out, err := launchctl(10*time.Second, "bootstrap", "system", LaunchDaemonPlist); err != nil {
			return fmt.Errorf("launchctl bootstrap: %s (%w)", out, err)
		}
	}
	if out, err := launchctl(10*time.Second, "kickstart", launchdTarget); err != nil {
		return fmt.Errorf("launchctl kickstart: %s (%w)", out, err)
	}
	return nil
}

// StopLaunchDaemon does not use engine IPC. launchd can terminate a legacy core
// even when its startup mutex or IPC handler is stuck.
func StopLaunchDaemon() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("system daemon stop requires root")
	}
	loaded, pid, err := daemonLoaded()
	if err != nil {
		return err
	}
	if loaded {
		if pid > 0 {
			_, _ = launchctl(3*time.Second, "kill", "SIGTERM", launchdTarget)
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				_, current, queryErr := daemonLoaded()
				if queryErr != nil {
					return queryErr
				}
				if current == 0 {
					pid = 0
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if pid > 0 {
				// Signal the launchd job identity, never an unverified process PID.
				if out, err := launchctl(3*time.Second, "kill", "SIGKILL", launchdTarget); err != nil {
					return fmt.Errorf("launchctl kill: %s (%w)", out, err)
				}
			}
		}
		if out, err := launchctl(45*time.Second, "bootout", launchdTarget); err != nil {
			return fmt.Errorf("launchctl bootout: %s (%w)", out, err)
		}
	}
	return stopInstalledSidecars()
}

func installedSidecars() (map[int]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/ps", "-ww", "-axo", "pid=,comm=").Output()
	if err != nil {
		return nil, err
	}
	expected := map[string]bool{}
	for _, name := range []string{"ciadpi", "sing-box"} {
		expected[filepath.Join(filepath.Dir(CanonicalBinary()), name)] = true
	}
	result := map[int]string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		index := strings.IndexAny(line, " \t")
		if index < 1 {
			continue
		}
		pid, err := strconv.Atoi(line[:index])
		command := strings.TrimSpace(line[index:])
		if err == nil && pid > 1 && expected[command] {
			result[pid] = command
		}
	}
	return result, nil
}

func stopInstalledSidecars() error {
	processes, err := installedSidecars()
	if err != nil {
		return fmt.Errorf("inspect installed sidecars: %w", err)
	}
	for pid := range processes {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	if len(processes) == 0 {
		return nil
	}
	time.Sleep(200 * time.Millisecond)
	remaining, err := installedSidecars()
	if err != nil {
		return err
	}
	for pid, path := range processes {
		// Recheck the executable before signalling a PID after the grace period.
		if remaining[pid] != path {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return err
		}
	}
	return nil
}
