//go:build darwin

package ipc

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixPingRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "core.sock")
	t.Setenv("OFFVEIL_IPC_SOCK", sock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewServer(pingHandler{})
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if st, err := os.Stat(sock); err == nil && st.Mode()&os.ModeSocket != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket not created")
		}
		time.Sleep(10 * time.Millisecond)
	}

	st, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket perm=%o want 0600", perm)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if err := json.NewEncoder(conn).Encode(Request{ID: "1", Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("resp=%+v", resp)
	}

	cancel()
	_ = srv.Close()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return")
	}
}

func TestSocketPathEnvOverride(t *testing.T) {
	t.Setenv("OFFVEIL_IPC_SOCK", "/tmp/offveil-test.sock")
	if got := SocketPath(); got != "/tmp/offveil-test.sock" {
		t.Fatalf("SocketPath()=%q", got)
	}
	if got := DialPath(); got != "/tmp/offveil-test.sock" {
		t.Fatalf("DialPath()=%q", got)
	}
}

func TestDefaultRootSocket(t *testing.T) {
	if DefaultRootSocket != "/var/run/offveil/core.sock" {
		t.Fatalf("DefaultRootSocket=%s", DefaultRootSocket)
	}
	if SocketGroup != "offveil" {
		t.Fatalf("SocketGroup=%s", SocketGroup)
	}
}

func TestWriteSocketOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipc-owner")
	t.Setenv("OFFVEIL_IPC_OWNER", path)
	if err := WriteSocketOwner("root"); err == nil {
		t.Fatal("root owner must be rejected")
	}
	if err := WriteSocketOwner("eray"); err != nil {
		t.Fatal(err)
	}
	if got := readSocketOwner(); got != "eray" {
		t.Fatalf("owner=%q", got)
	}
}

func TestUnlinkStaleRejectsLive(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "v.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := unlinkStaleSocket(sock); err == nil {
		t.Fatal("expected error when socket is live")
	}
}

func TestRemoveIdleSocketLeavesLive(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "l.sock")
	ln, err := net.Listen("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := RemoveIdleSocket(live); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatal("live socket must stay")
	}

	stale := filepath.Join(dir, "s.sock")
	sln, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	_ = sln.Close()
	if err := RemoveIdleSocket(stale); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale socket must be removed")
	}
}
