package appservice

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServiceStartRejectsMissingIPCListener(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	p := NewProgram()
	p.serveIPC = func(context.Context) error { return errors.New("injected listener failure") }
	p.exitProcess = func(int) { t.Error("startup failure must return to the service manager") }
	if err := p.Start(nil); err == nil {
		t.Fatal("service reported healthy without a listener")
	}
}

func TestServiceStartWaitsForListenerAndNormalStopDoesNotExit(t *testing.T) {
	p := NewProgram()
	ready, entered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	p.ipcReady = ready
	p.serveIPC = func(ctx context.Context) error {
		close(entered)
		<-release
		close(ready)
		<-ctx.Done()
		return nil
	}
	exit := make(chan int, 1)
	p.exitProcess = func(code int) { exit <- code }
	started := make(chan error, 1)
	go func() { started <- p.Start(nil) }()
	<-entered
	select {
	case err := <-started:
		t.Fatalf("started before listener: %v", err)
	default:
	}
	close(release)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exit:
		t.Fatal("intentional stop triggered crash recovery")
	default:
	}
}

func TestListenerLossRestoresOwnedStateBeforeFailureExit(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	p := NewProgram()
	ready, failed, restored := make(chan struct{}), make(chan struct{}), make(chan struct{})
	p.ipcReady = ready
	p.serveIPC = func(context.Context) error { close(ready); <-failed; return errors.New("injected accept failure") }
	p.reg.Register("test-owned-state", func() error { close(restored); return nil })
	exit := make(chan int, 1)
	p.exitProcess = func(code int) { exit <- code }
	if err := p.Start(nil); err != nil {
		t.Fatal(err)
	}
	close(failed)
	select {
	case code := <-exit:
		if code != 1 {
			t.Fatalf("exit=%d", code)
		}
		select {
		case <-restored:
		default:
			t.Fatal("exited without cleanup")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener loss left a running phantom service")
	}
}
