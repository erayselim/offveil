//go:build darwin

package ipc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/erayselim/offveil/offveil-core/internal/appdir"
)

// DefaultRootSocket is the LaunchDaemon path (root listens, UI user connects).
const DefaultRootSocket = "/var/run/offveil/core.sock"

// SocketGroup may connect when the daemon is root (0660). Setup creates it.
const SocketGroup = "offveil"

func endpoint() string { return DialPath() }

// SocketPath is where this process binds.
//
//	OFFVEIL_IPC_SOCK  — explicit override (CI / tests)
//	root              — /var/run/offveil/core.sock
//	interactive       — $TMPDIR/offveil-<uid>/core.sock
func SocketPath() string {
	if p := strings.TrimSpace(os.Getenv("OFFVEIL_IPC_SOCK")); p != "" {
		return p
	}
	if os.Geteuid() == 0 {
		return DefaultRootSocket
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("offveil-%d", os.Getuid()), "core.sock")
}

// DialPath is where the UI and `offveil-core client` connect.
// A non-root client prefers the LaunchDaemon socket when it exists.
func DialPath() string {
	if p := strings.TrimSpace(os.Getenv("OFFVEIL_IPC_SOCK")); p != "" {
		return p
	}
	if isSocket(DefaultRootSocket) {
		return DefaultRootSocket
	}
	return SocketPath()
}

func isSocket(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// OwnerPath is the username that may own the root socket (no re-login wait).
func OwnerPath() string {
	if p := strings.TrimSpace(os.Getenv("OFFVEIL_IPC_OWNER")); p != "" {
		return p
	}
	return filepath.Join(appdir.Root(), "ipc-owner")
}

// WriteSocketOwner records the UI user from setup. Empty/root rejected.
func WriteSocketOwner(username string) error {
	username = strings.TrimSpace(username)
	if username == "" || username == "root" {
		return fmt.Errorf("ipc: invalid socket owner")
	}
	path := OwnerPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(username+"\n"), 0o644)
}

func readSocketOwner() string {
	b, err := os.ReadFile(OwnerPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ListenAndServe binds a pathname unix socket. Not abstract; not remote.
func (s *Server) ListenAndServe(ctx context.Context) error {
	path := SocketPath()
	if err := prepareSocketPath(path); err != nil {
		return err
	}
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return fmt.Errorf("ipc: resolve %s: %w", path, err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", path, err)
	}
	ln.SetUnlinkOnClose(true)
	if err := applySocketPerms(path); err != nil {
		_ = ln.Close()
		return err
	}
	slog.Info("ipc: listening", "socket", path)
	return s.serveListener(ctx, ln)
}

func prepareSocketPath(path string) error {
	if path == "" || strings.Contains(path, "\x00") {
		return fmt.Errorf("ipc: invalid socket path")
	}
	dir := filepath.Dir(path)
	mode := os.FileMode(0o700)
	if os.Geteuid() == 0 {
		// 0755 so the UI user can reach the socket before group membership
		// is in the login token.
		mode = 0o755
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return fmt.Errorf("ipc: mkdir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, mode)
	return unlinkStaleSocket(path)
}

func unlinkStaleSocket(path string) error {
	conn, err := net.Dial("unix", path)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("ipc: already listening on %s", path)
	}
	if os.IsNotExist(err) {
		return nil
	}
	if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
		return fmt.Errorf("ipc: remove stale %s: %w", path, rmErr)
	}
	return nil
}

// RemoveIdleSocket unlinks a pathname socket that nothing is accepting.
// A live listener is left alone (uninstall after launchd stop).
func RemoveIdleSocket(path string) error {
	if path == "" {
		return nil
	}
	conn, err := net.Dial("unix", path)
	if err == nil {
		_ = conn.Close()
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
		return rmErr
	}
	return nil
}

func applySocketPerms(path string) error {
	if os.Geteuid() != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("ipc: chmod 0600 %s: %w", path, err)
		}
		return nil
	}
	if uid, gid, ok := socketOwnerIDs(); ok {
		if err := os.Chown(path, uid, gid); err != nil {
			slog.Warn("ipc: chown owner", "uid", uid, "err", err)
		} else if err := os.Chmod(path, 0o660); err != nil {
			return fmt.Errorf("ipc: chmod 0660 %s: %w", path, err)
		} else {
			return nil
		}
	}
	if chownOffveilGroup(path) {
		if err := os.Chmod(path, 0o660); err != nil {
			return fmt.Errorf("ipc: chmod 0660 %s: %w", path, err)
		}
		return nil
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("ipc: chmod 0600 %s: %w", path, err)
	}
	slog.Info("ipc: socket 0600 (group offveil missing; UI user cannot connect until setup)")
	return nil
}

func socketOwnerIDs() (uid, gid int, ok bool) {
	name := readSocketOwner()
	if name == "" {
		return 0, 0, false
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, false
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil || uid <= 0 {
		return 0, 0, false
	}
	if g, err := user.LookupGroup(SocketGroup); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	}
	if gid == 0 && u.Gid != "" {
		gid, _ = strconv.Atoi(u.Gid)
	}
	return uid, gid, true
}

func chownOffveilGroup(path string) bool {
	g, err := user.LookupGroup(SocketGroup)
	if err != nil {
		return false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return false
	}
	if err := os.Chown(path, 0, gid); err != nil {
		slog.Warn("ipc: chown", "path", path, "err", err)
		return false
	}
	return true
}
