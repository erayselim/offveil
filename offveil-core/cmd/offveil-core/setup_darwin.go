//go:build darwin

package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/kardianos/service"

	"github.com/erayselim/offveil/offveil-core/internal/appdir"
	"github.com/erayselim/offveil/offveil-core/internal/appservice"
	"github.com/erayselim/offveil/offveil-core/internal/crashlog"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/sidecar"
)

func elevateIfNeeded(action string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	if os.Getenv("OFFVEIL_NO_ELEVATE") != "" {
		return fmt.Errorf("%s requires root", action)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	script := appservice.ElevateScript(exe, setupUserName(), action)
	cmd := exec.Command("osascript", "-e", script)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: admin prompt failed: %w", action, err)
	}
	os.Exit(0)
	return nil
}

func prepareServiceInstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install requires root")
	}
	if err := os.MkdirAll(appdir.Root(), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(crashlog.Dir(), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll("/var/run/offveil", 0o755); err != nil {
		return err
	}
	if err := installCanonicalBinary(); err != nil {
		return err
	}
	if err := installSidecars(); err != nil {
		return err
	}
	ensureOffveilGroup()
	if who := setupUserName(); who != "" {
		addUserToGroup(who)
		if err := ipc.WriteSocketOwner(who); err != nil {
			slog.Warn("setup: ipc owner", "err", err)
		}
	}
	return nil
}

func afterInstall() { writeSudoers() }

func afterUninstall() {
	if err := os.Remove(appservice.SudoersPath); err != nil && !os.IsNotExist(err) {
		slog.Warn("uninstall: sudoers", "err", err)
	}
	if err := ipc.RemoveIdleSocket(ipc.DefaultRootSocket); err != nil {
		slog.Warn("uninstall: socket", "err", err)
	}
}

func configureDemandStart() { writeSudoers() }

func startService(svc service.Service) error {
	_ = svc
	if os.Geteuid() != 0 {
		return sudoCanonical("start")
	}
	return launchdLoadAndStart()
}

func stopService(svc service.Service) error {
	if os.Geteuid() != 0 {
		return sudoCanonical("stop")
	}
	return svc.Stop()
}

func sudoCanonical(action string) error {
	exe := appservice.CanonicalBinary()
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("%s offveil-core LaunchDaemon not installed", appservice.NeedsInstallPrefix)
	}
	cmd := exec.Command("sudo", "-n", exe, action)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s passwordless %s failed (run setup): %w", appservice.NeedsInstallPrefix, action, err)
	}
	os.Exit(0)
	return nil
}

func launchdLoadAndStart() error {
	plist := appservice.LaunchDaemonPlist
	out, err := exec.Command("launchctl", "load", plist).CombinedOutput()
	if err != nil && !alreadyLoaded(string(out), err) {
		return fmt.Errorf("launchctl load: %s (%w)", bytesTrim(out), err)
	}
	out, err = exec.Command("launchctl", "start", appservice.Name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl start: %s (%w)", bytesTrim(out), err)
	}
	return nil
}

func alreadyLoaded(out string, err error) bool {
	s := strings.ToLower(out)
	if err != nil {
		s += " " + strings.ToLower(err.Error())
	}
	return strings.Contains(s, "already loaded") ||
		strings.Contains(s, "already bootstrapped") ||
		strings.Contains(s, "service is already loaded")
}

func bytesTrim(b []byte) string {
	return strings.TrimSpace(string(b))
}

func writeSudoers() {
	body := appservice.SudoersBody(appservice.CanonicalBinary())
	tmp, err := os.CreateTemp("", "offveil-sudoers-")
	if err != nil {
		slog.Warn("setup: sudoers temp", "err", err)
		return
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpName)
	if err := os.WriteFile(tmpName, []byte(body), 0o440); err != nil {
		slog.Warn("setup: sudoers write temp", "err", err)
		return
	}
	if out, err := exec.Command("visudo", "-cf", tmpName).CombinedOutput(); err != nil {
		slog.Warn("setup: visudo -c", "err", err, "out", bytesTrim(out))
		return
	}
	if err := os.WriteFile(appservice.SudoersPath, []byte(body), 0o440); err != nil {
		slog.Warn("setup: sudoers install", "err", err)
		return
	}
	slog.Info("setup: sudoers NOPASSWD start/stop (%admin)")
}

func installCanonicalBinary() error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		src = resolved
	}
	dst := appservice.CanonicalBinary()
	if sameFile(src, dst) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if syncErr != nil {
		_ = os.Remove(tmp)
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(dst, 0o755)
	_ = os.Chown(dst, 0, 0)
	if err := sidecar.Sign(dst); err != nil {
		return fmt.Errorf("codesign offveil-core: %w", err)
	}
	slog.Info("setup: installed binary", "path", dst)
	return nil
}

func installSidecars() error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		src = resolved
	}
	srcDir := filepath.Dir(src)
	destDir := filepath.Dir(appservice.CanonicalBinary())
	for _, base := range []string{sidecar.ByeDPI, sidecar.SingBox} {
		in, err := sidecar.LocateInDir(srcDir, base)
		if err != nil {
			slog.Warn("setup: sidecar not beside installer", "name", base)
			continue
		}
		dst := filepath.Join(destDir, sidecar.Names(base)[0])
		if err := sidecar.CopySigned(in, dst); err != nil {
			return fmt.Errorf("sidecar %s: %w", base, err)
		}
		_ = os.Chown(dst, 0, 0)
		slog.Info("setup: installed sidecar", "path", dst)
	}
	return nil
}

func sameFile(a, b string) bool {
	sa, errA := os.Stat(a)
	sb, errB := os.Stat(b)
	if errA != nil || errB != nil {
		return false
	}
	return os.SameFile(sa, sb)
}

func ensureOffveilGroup() {
	cmd := exec.Command("dseditgroup", "-o", "create", "-n", "/Local/Default", "-r", "offveil IPC", ipc.SocketGroup)
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Info("setup: group", "out", bytesTrim(out), "err", err)
	}
}

func addUserToGroup(username string) {
	cmd := exec.Command("dseditgroup", "-o", "edit", "-n", "/Local/Default", "-a", username, "-t", "user", ipc.SocketGroup)
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("setup: add user to group", "user", username, "out", bytesTrim(out), "err", err)
		return
	}
	slog.Info("setup: user in group", "user", username, "group", ipc.SocketGroup)
}

func setupUserName() string {
	for _, k := range []string{"OFFVEIL_SETUP_USER", "SUDO_USER"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" && v != "root" {
			return v
		}
	}
	if u, err := user.Current(); err == nil && u.Username != "" && u.Username != "root" {
		return u.Username
	}
	if st, err := os.Stat("/dev/console"); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 {
			if u, err := user.LookupId(strconv.Itoa(int(sys.Uid))); err == nil {
				return u.Username
			}
		}
	}
	return ""
}

func probeStatus() (string, bool) {
	if _, err := os.Stat(appservice.LaunchDaemonPlist); err != nil {
		if os.IsNotExist(err) {
			return "not installed", true
		}
		return "", false
	}
	if st, err := os.Stat(ipc.DefaultRootSocket); err == nil && st.Mode()&os.ModeSocket != 0 {
		return "running", true
	}
	return "stopped", true
}
