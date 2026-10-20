package proc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func TestReadinessWaitHonorsOwningSessionCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	began := time.Now()
	if err := WaitTCPContext(ctx, "127.0.0.1:1", time.Minute, nil); !errors.Is(err, context.Canceled) || time.Since(began) > time.Second {
		t.Fatalf("canceled session kept waiting: %v", err)
	}
}

func TestChildHelper(t *testing.T) {
	switch os.Getenv("OFFVEIL_CHILD_TEST") {
	case "exit":
		os.Exit(7)
	case "wait":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func childForTest(t *testing.T, mode string) *Child {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestChildHelper$")
	cmd.Env = append(os.Environ(), "OFFVEIL_CHILD_TEST="+mode)
	cmd.Stderr = &TailBuffer{}
	PrepareCmd(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child := WatchChild(cmd)
	t.Cleanup(child.Close)
	return child
}

func TestChildReapsUnexpectedExitAndStopsReadinessWait(t *testing.T) {
	c := childForTest(t, "exit")
	began := time.Now()
	if err := WaitTCP("127.0.0.1:1", 10*time.Second, c); err == nil {
		t.Fatal("exited child reported ready")
	}
	if c.Running() || c.err == nil || time.Since(began) > 5*time.Second {
		t.Fatal("child exit was not promptly observed and reaped")
	}
	info := c.Exit()
	if info == nil || info.Code != 7 || info.At == "" || info.Error == "" {
		t.Fatalf("missing exit facts: %+v", info)
	}
	info.Code = 0
	if c.Exit().Code != 7 {
		t.Fatal("caller modified the recorded exit")
	}
}

func TestStderrClassOmitsLogContents(t *testing.T) {
	if got := stderrClass("accept: too many open files /Users/private token=secret"); got != "file_limit" {
		t.Fatalf("class=%q", got)
	}
	if got := stderrClass("https://private.example/?token=secret"); got != "other" {
		t.Fatalf("class=%q", got)
	}
	for _, tc := range []struct{ stderr, want string }{
		{"FATAL[0020] start service: unspecified failure", "fatal"},
		{"FATAL[0000] start inbound/tun[tun-in]: create adapter: failed", "tun_setup"},
		{"FATAL[0000] decode config at C:\\private: invalid key", "config_invalid"},
		{"Only one usage of each socket address is normally permitted", "address_in_use"},
		{"wsasend: no buffer space available token=secret", "socket_limit"},
		{"Access is denied C:\\private", "permission_denied"},
	} {
		if got := stderrClass(tc.stderr); got != tc.want {
			t.Errorf("class=%q want %q", got, tc.want)
		}
	}
}

func TestTransientAdapterReasonsAreSpecificAndRedacted(t *testing.T) {
	for _, tc := range []struct{ stderr, want string }{
		{"FATAL configure tun interface: Cannot create a file when that file already exists. token=secret", "adapter_exists"},
		{"FATAL configure tun interface: Zaten var olan bir dosya oluşturulamaz.", "adapter_exists"},
		{"create adapter: The device is being removed", "adapter_removing"},
		{"configure tun interface: The requested resource is in use", "adapter_busy"},
		{"configure tun interface: Access is denied", "access_denied"},
		{"dial tcp: The requested resource is in use token=secret", ""},
	} {
		if got := stderrReason(tc.stderr); got != tc.want {
			t.Errorf("reason=%q want %q", got, tc.want)
		}
	}
}

func TestChildConcurrentCloseWaitsOnce(t *testing.T) {
	c := childForTest(t, "wait")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(c.Close)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent process shutdown did not complete")
	}
	if c.Running() {
		t.Fatal("closed child still running")
	}
}
