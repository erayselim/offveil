package engine

import (
	"errors"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func TestRecoveryLeavesHealthyDataplaneRunning(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	e := activeBackgroundEngine(t)
	dead := desync.NewFakeSession(desync.Info{})
	_ = dead.Close()
	e.des = dead
	tun := tunnel.NewFakeSession(tunnel.Info{Up: true})
	e.tun = tun
	e.desyncConfig = &desync.Config{ProbeHost: "discord.com"}
	calls := 0
	e.startDesync = func(cfg desync.Config) (desync.Session, error) {
		if cfg.ProbeHost != "" {
			t.Fatal("process recovery can rewrite the accepted routing policy")
		}
		calls++
		return desync.NewFakeSession(desync.Info{}), nil
	}
	e.recoverComponent(e.sessionGeneration, time.Now())
	st := e.Status()
	if calls != 1 || st.State != StateActive || st.LastError != nil || tun.Closed() {
		t.Fatalf("calls=%d state=%+v tunClosed=%v", calls, st, tun.Closed())
	}
	history := diag.ReadFailures()
	if len(history) != 2 || history[0].Event != "unavailable" || history[1].Event != "recovered" {
		t.Fatalf("history=%+v", history)
	}
}

type failedDNSCleanup struct{ offdns.Session }

func (failedDNSCleanup) Close() error { return errors.New("DNS restoration failed") }

func TestRecoveryDoesNotRestartAfterFailedDNSCleanup(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	e := activeBackgroundEngine(t)
	dead := offdns.NewFakeSession(offdns.Info{})
	_ = dead.Close()
	e.dns = failedDNSCleanup{dead}
	e.dnsConfig = &offdns.Config{}
	calls := 0
	e.startDNS = func(offdns.Config) (offdns.Session, error) {
		calls++
		return nil, nil
	}
	e.recoverComponent(e.sessionGeneration, time.Now())
	e.recoverComponent(e.sessionGeneration, time.Now().Add(recoveryCooldown))
	if calls != 0 || e.Status().State != StateDegraded {
		t.Fatal("recovery continued after failed DNS restoration")
	}
}

func TestRecoveryBudgetAndSessionOwnership(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	e := activeBackgroundEngine(t)
	dead := desync.NewFakeSession(desync.Info{})
	_ = dead.Close()
	e.des = dead
	e.desyncConfig = &desync.Config{}
	calls := 0
	e.startDesync = func(desync.Config) (desync.Session, error) {
		calls++
		return nil, errors.New("injected failure")
	}
	generation := e.sessionGeneration
	now := time.Now()
	for i := range 6 {
		e.recoverComponent(generation, now.Add(time.Duration(i)*recoveryCooldown))
	}
	if calls != recoveryBudget || e.Status().State != StateDegraded {
		t.Fatalf("calls=%d state=%s", calls, e.Status().State)
	}
	e.mu.Lock()
	e.cancelSessionLocked()
	e.mu.Unlock()
	e.recoverComponent(generation, now.Add(time.Hour))
	if calls != recoveryBudget {
		t.Fatal("cancelled session restarted a component")
	}
}

func TestRecoveryPreservesUnavailableProtectedPath(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	e := activeBackgroundEngine(t)
	message := "tunnel: protected path unavailable"
	e.pathError = &message
	dead := desync.NewFakeSession(desync.Info{})
	_ = dead.Close()
	e.des = dead
	e.desyncConfig = &desync.Config{}
	e.startDesync = func(desync.Config) (desync.Session, error) {
		return desync.NewFakeSession(desync.Info{}), nil
	}
	e.recoverComponent(e.sessionGeneration, time.Now())
	st := e.Status()
	if st.State != StateDegraded || st.LastError == nil || *st.LastError != message {
		t.Fatalf("component recovery masked a failed protected path: %+v", st)
	}
}
