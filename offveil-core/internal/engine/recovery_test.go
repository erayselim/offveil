package engine

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/cleanup"
	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
	"github.com/erayselim/offveil/offveil-core/internal/proc"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func TestRecoveryLeavesHealthyDataplaneRunning(t *testing.T) {
	e := networkTestEngine(t, "remote")
	dead := e.des.(*desync.FakeSession)
	_ = dead.Close()
	gateway := e.tun.(*tunnel.FakeSession)
	calls := 0
	e.startDesync = func(cfg desync.Config) (desync.Session, error) {
		if cfg.ProbeHost != "" {
			t.Fatal("component recovery triggered endpoint routing")
		}
		calls++
		return desync.NewFakeSession(desync.Info{Up: true}), nil
	}
	e.recoverComponent(e.sessionGeneration, time.Now())
	if st := e.Status(); calls != 1 || st.State != StateActive || st.LastError != nil || gateway.Closed() {
		t.Fatalf("helper recovery disrupted transport: %+v", st)
	}
	history := diag.ReadFailures()
	if len(history) != 2 || history[0].Event != "unavailable" || history[1].Event != "recovered" {
		t.Fatalf("history=%+v", history)
	}
}

type failedDNSCleanup struct{ offdns.Session }

func (failedDNSCleanup) Close() error { return errors.New("fixture DNS restoration failed") }

func TestRecoveryDoesNotRestartAfterFailedDNSCleanup(t *testing.T) {
	e := networkTestEngine(t, "remote")
	dead := offdns.NewFakeSession(offdns.Info{})
	_ = dead.Close()
	e.dns = failedDNSCleanup{dead}
	e.dnsConfig = &offdns.Config{}
	calls := 0
	e.startDNS = func(offdns.Config) (offdns.Session, error) { calls++; return nil, nil }
	e.recoverComponent(e.sessionGeneration, time.Now())
	e.recoverComponent(e.sessionGeneration, time.Now().Add(recoveryCooldown))
	if calls != 0 || e.Status().State != StateDegraded {
		t.Fatal("recovery continued after failed DNS restoration")
	}
}

func TestRecoveryBudgetAndSessionOwnership(t *testing.T) {
	e := networkTestEngine(t, "local")
	_ = e.des.Close()
	calls := 0
	e.startDesync = func(desync.Config) (desync.Session, error) {
		calls++
		return nil, errors.New("fixture restart failure")
	}
	generation, now := e.sessionGeneration, time.Now()
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

func TestComponentRecoveryKeepsLimitedCoverageAndFailedControls(t *testing.T) {
	e := networkTestEngine(t, "local")
	e.networkFailures = 2
	_ = e.des.Close()
	e.startDesync = func(desync.Config) (desync.Session, error) { return desync.NewFakeSession(desync.Info{Up: true}), nil }
	e.recoverComponent(e.sessionGeneration, time.Now())
	if st := e.Status(); st.State != StateDegraded || st.LastError == nil || e.networkCheck.Reason != "control_quorum_failed" || e.networkCheck.Coverage != "tls_http_only" {
		t.Fatalf("process recovery erased network state: %+v %+v", st, e.networkCheck)
	}
}

func TestRequiredGatewayTakesPriorityOverDeadOptionalHelper(t *testing.T) {
	e := networkTestEngine(t, "remote")
	_ = e.des.Close()
	_ = e.tun.Close()
	var helpers, gateways int
	e.startDesync = func(desync.Config) (desync.Session, error) {
		helpers++
		return nil, errors.New("optional helper remains unavailable")
	}
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) {
		gateways++
		return tunnel.NewFakeSession(tunnel.Info{Mode: "remote", ProviderID: tunnel.ProviderWARP, Up: true, Healthy: true}), nil
	}
	e.recoverComponent(e.sessionGeneration, time.Now())
	if st := e.Status(); gateways != 1 || helpers != 0 || st.State != StateActive {
		t.Fatalf("optional failure masked required transport: gateways=%d helpers=%d status=%+v", gateways, helpers, st)
	}
}

func TestComponentRecoveryDoesNotBlockStopOrAdoptLateSession(t *testing.T) {
	e := networkTestEngine(t, "local")
	_ = e.des.Close()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	late := desync.NewFakeSession(desync.Info{Up: true})
	e.startDesync = func(desync.Config) (desync.Session, error) { close(entered); <-release; return late, nil }
	generation := e.sessionGeneration
	go func() { defer close(done); e.recoverComponent(generation, time.Now()) }()
	awaitBackground(t, entered)
	stopped := make(chan struct{})
	go func() { _, _ = e.Stop(); close(stopped) }()
	awaitBackground(t, stopped)
	close(release)
	awaitBackground(t, done)
	if !late.Closed() || e.Status().Protection {
		t.Fatal("late component survived Stop")
	}
}

func startedNetworkFixture(t *testing.T, dnsStart DNSStartFunc) *Engine {
	t.Helper()
	t.Setenv("OFFVEIL_NETWORK_BG", "0")
	t.Setenv("OFFVEIL_DESYNC_CACHE", t.TempDir())
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	e := New(cleanup.NewRegistry())
	e.loadRuleset = func(context.Context) (ruleset.Snapshot, error) { return ruleset.MustLoadEmbedded(), nil }
	e.lookupNet = func(context.Context) netinfo.Info { return netinfo.Info{ASN: "64512", Fingerprint: "fixture"} }
	e.startCapture = func(capture.Config) (capture.Session, error) { return capture.NewFakeSession(capture.Info{}), nil }
	e.startDNS = dnsStart
	e.startDesync = func(desync.Config) (desync.Session, error) { return desync.NewFakeSession(desync.Info{Up: true}), nil }
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) {
		return tunnel.NewFakeSession(tunnel.Info{Mode: "remote", ProviderID: tunnel.ProviderWARP, Up: true, Healthy: true}), nil
	}
	if _, err := e.Start("auto"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = e.Stop() })
	return e
}

func TestStopClosesReplacementDNSAfterComponentRecovery(t *testing.T) {
	old, next := offdns.NewFakeSession(offdns.Info{}), offdns.NewFakeSession(offdns.Info{})
	calls := 0
	e := startedNetworkFixture(t, func(offdns.Config) (offdns.Session, error) {
		calls++
		if calls == 1 {
			return old, nil
		}
		return next, nil
	})
	_ = old.Close()
	e.recoverComponent(e.sessionGeneration, time.Now())
	if !next.Info().StubUp || calls != 2 {
		t.Fatal("resolver was not replaced")
	}
	_, _ = e.Stop()
	if next.Info().StubUp {
		t.Fatal("Stop cleaned only the old DNS session")
	}
}

func TestStartupFailureReplacesPreviousSuccessfulDiagnostics(t *testing.T) {
	e := startedNetworkFixture(t, func(offdns.Config) (offdns.Session, error) { return offdns.NewFakeSession(offdns.Info{}), nil })
	_, _ = e.Stop()
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) { return nil, errors.New("fixture gateway startup failure") }
	if _, err := e.Start("auto"); err == nil {
		t.Fatal("expected gateway startup failure")
	}
	e.mu.Lock()
	report := e.diagnosticsInputLocked()
	e.mu.Unlock()
	if report.Cascade.Protection || report.Cascade.State != StateStopped || !strings.Contains(report.Cascade.LastError, "fixture gateway startup failure") {
		t.Fatalf("new startup failure masked by retained success: %+v", report.Cascade)
	}
}

func TestStartupFailurePersistsGatewayFactsAfterEngineReplacement(t *testing.T) {
	e := startedNetworkFixture(t, func(offdns.Config) (offdns.Session, error) {
		return offdns.NewFakeSession(offdns.Info{}), nil
	})
	_, _ = e.Stop()
	exit := &proc.ExitInfo{Code: 1, StderrClass: "tun_setup", Reason: "adapter_busy"}
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) {
		return nil, &tunnel.StartupError{Err: errors.New("fixture gateway startup failure"), Failures: []tunnel.ProviderFailure{
			{ProviderID: tunnel.ProviderWARP, Stage: "control_tls", Class: tunnel.FailEOF, ExitOrigin: "cleanup"},
			{ProviderID: tunnel.ProviderDesync, Stage: "gateway_startup", Class: tunnel.FailDial, Exit: exit, ExitOrigin: "natural"},
		}}
	}
	if _, err := e.Start("auto"); err == nil {
		t.Fatal("fixture gateway unexpectedly started")
	}
	report := e.diagnosticsInputLocked()
	if report.Cascade.Protection || report.Sidecars["tunnel"] == nil || report.Sidecars["capture"] == nil {
		t.Fatal("cleanup discarded the failed startup stack")
	}
	// A fresh engine has no previous in-memory snapshot, just like an offline
	// collector after the service stopped. The durable journal keeps the layer.
	_ = New(cleanup.NewRegistry())
	history := diag.ReadFailures()
	if len(history) != 3 || history[0].Stage != "control_tls" || history[0].Class != "eof" ||
		history[1].ExitOrigin != "natural" || history[1].Exit == nil || history[1].Exit.Reason != "adapter_busy" ||
		history[2].Reason != "tun_failed" || history[2].Stage != "gateway_startup" || history[2].Class != "dial" {
		t.Fatalf("offline startup evidence lost: %+v", history)
	}
}

func TestCaptureFailureIsDistinctFromGatewayStartup(t *testing.T) {
	e := startedNetworkFixture(t, func(offdns.Config) (offdns.Session, error) {
		return offdns.NewFakeSession(offdns.Info{}), nil
	})
	_, _ = e.Stop()
	e.startCapture = func(capture.Config) (capture.Session, error) {
		return nil, context.DeadlineExceeded
	}
	if _, err := e.Start("auto"); err == nil {
		t.Fatal("fixture capture unexpectedly started")
	}
	history := diag.ReadFailures()
	if len(history) != 1 || history[0].Stage != "capture" || history[0].Class != "timeout" || history[0].Reason != "tun_failed" {
		t.Fatalf("capture error collapsed into generic TUN failure: %+v", history)
	}
}

type unavailableAdapter struct {
	capture.Session
	attempts atomic.Int32
}

func (s *unavailableAdapter) AttachAdapter(string) error {
	s.attempts.Add(1)
	return errors.New("fixture adapter not ready")
}

func TestAdapterReadinessHonorsSessionDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	cap := &unavailableAdapter{Session: capture.NewFakeSession(capture.Info{})}
	started := time.Now()
	err := attachCaptureAdapter(ctx, cap, "fixture")
	if !errors.Is(err, context.DeadlineExceeded) || cap.attempts.Load() == 0 || time.Since(started) > time.Second {
		t.Fatalf("adapter readiness ignored cancellation: %v", err)
	}
}
