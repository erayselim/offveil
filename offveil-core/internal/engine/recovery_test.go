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

func eventsOf(history []diag.Failure, component string) []diag.Failure {
	var out []diag.Failure
	for _, f := range history {
		if f.Component == component {
			out = append(out, f)
		}
	}
	return out
}

func TestRecoveryLeavesHealthyDataplaneRunning(t *testing.T) {
	e, gateway := networkTestEngine(t)
	dead := e.des.(*desync.FakeSession)
	_ = dead.Close()
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
	history := eventsOf(diag.ReadFailures(), "desync")
	if len(history) != 2 || history[0].Event != "unavailable" || history[1].Event != "recovered" {
		t.Fatalf("history=%+v", history)
	}
}

type failedDNSCleanup struct{ offdns.Session }

func (failedDNSCleanup) Close() error { return errors.New("fixture DNS restoration failed") }

func TestRecoveryDoesNotRestartAfterFailedDNSCleanup(t *testing.T) {
	e, _ := networkTestEngine(t)
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
	e, _ := networkTestEngine(t)
	_ = e.des.Close()
	calls := 0
	e.startDesync = func(desync.Config) (desync.Session, error) {
		calls++
		return nil, errors.New("fixture restart failure")
	}
	generation, now := e.sessionGeneration, time.Now()
	if st := e.Status(); st.State != StateActive || st.Transition != "transport_recovery" {
		t.Fatalf("pending recovery must read as reconnecting: %+v", st)
	}
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

func TestComponentRecoveryKeepsGroupState(t *testing.T) {
	e, _ := networkTestEngine(t)
	e.groupLocked("chat").Unreachable = true
	_ = e.des.Close()
	e.startDesync = func(desync.Config) (desync.Session, error) { return desync.NewFakeSession(desync.Info{Up: true}), nil }
	e.recoverComponent(e.sessionGeneration, time.Now())
	if st := e.Status(); st.State != StateActive || st.Summary != "Sınırlı koruma" || e.networkCheck.Reason != ReasonGroup {
		t.Fatalf("process recovery erased group state: %+v %+v", st, e.networkCheck)
	}
}

func TestGatewayIsRecoveredBeforeHelper(t *testing.T) {
	e, _ := networkTestEngine(t)
	_ = e.des.Close()
	_ = e.tun.Close()
	var helpers, gateways int
	e.startDesync = func(desync.Config) (desync.Session, error) {
		helpers++
		return nil, errors.New("helper remains unavailable")
	}
	e.startTunnel = func(cfg tunnel.Config) (tunnel.Session, error) {
		gateways++
		if !cfg.Selective {
			t.Fatal("recovery lost the selective configuration")
		}
		return newGatewayFixture(false), nil
	}
	e.recoverComponent(e.sessionGeneration, time.Now())
	if st := e.Status(); gateways != 1 || helpers != 0 || st.State != StateActive || st.Transition != "transport_recovery" {
		t.Fatalf("gateways=%d helpers=%d status=%+v", gateways, helpers, st)
	}
}

func TestComponentRecoveryDoesNotBlockStopOrAdoptLateSession(t *testing.T) {
	e, _ := networkTestEngine(t)
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
	e.closeOrphan, e.takeSnapshot = nil, nil
	e.classify = func(context.Context, DirectProbe, []string, []ruleset.CanaryGroup) Classification {
		return Classification{DPI: DPIPresent}
	}
	e.loadRuleset = func(context.Context) (ruleset.Snapshot, error) { return ruleset.MustLoadEmbedded(), nil }
	e.lookupNet = func(context.Context) netinfo.Info { return netinfo.Info{ASN: "64512", Fingerprint: "fixture"} }
	e.startCapture = func(capture.Config) (capture.Session, error) { return capture.NewFakeSession(capture.Info{}), nil }
	e.startDNS = dnsStart
	e.startDesync = func(desync.Config) (desync.Session, error) { return desync.NewFakeSession(desync.Info{Up: true}), nil }
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) { return newGatewayFixture(false), nil }
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
	e.startCapture = func(capture.Config) (capture.Session, error) {
		return nil, errors.New("fixture capture startup failure")
	}
	if _, err := e.Start("auto"); err == nil {
		t.Fatal("expected capture startup failure")
	}
	e.mu.Lock()
	report := e.diagnosticsInputLocked()
	e.mu.Unlock()
	if report.Cascade.Protection || report.Cascade.State != StateStopped || !strings.Contains(report.Cascade.LastError, "fixture capture startup failure") {
		t.Fatalf("new startup failure masked by retained success: %+v", report.Cascade)
	}
}

func TestGatewayStartupFailureIsJournaledAndFallsBackToDNS(t *testing.T) {
	e := startedNetworkFixture(t, func(offdns.Config) (offdns.Session, error) {
		return offdns.NewFakeSession(offdns.Info{}), nil
	})
	_, _ = e.Stop()
	exit := &proc.ExitInfo{Code: 1, StderrClass: "tun_setup", Reason: "adapter_busy"}
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) {
		return nil, &tunnel.StartupError{Err: errors.New("fixture gateway startup failure"), Failures: []tunnel.ProviderFailure{
			{ProviderID: tunnel.ProviderDesync, Stage: "gateway_startup", Class: tunnel.FailDial, Exit: exit, ExitOrigin: "natural"},
		}}
	}
	st, err := e.Start("auto")
	if err != nil || !st.Protection || st.Summary != "Sınırlı koruma" {
		t.Fatalf("fallback: status=%+v err=%v", st, err)
	}
	// A fresh engine has no in-memory snapshot, like an offline collector
	// after the service stopped. The durable journal keeps the facts.
	_ = New(cleanup.NewRegistry())
	var attempt, layer, fallback bool
	for _, f := range diag.ReadFailures() {
		switch f.Event {
		case "startup_attempt_failed":
			attempt = f.Stage == "gateway_startup" && f.Exit != nil && f.Exit.Reason == "adapter_busy" && f.ExitOrigin == "natural"
		case "layer_failed":
			layer = f.Stage == "gateway_startup"
		case "dns_only_fallback":
			fallback = true
		}
	}
	if !attempt || !layer || !fallback {
		t.Fatalf("startup evidence lost: %+v", diag.ReadFailures())
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
	history := eventsOf(diag.ReadFailures(), "engine")
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
	err := attachCaptureAdapter(ctx, cap, "fixture", nil)
	if !errors.Is(err, context.DeadlineExceeded) || cap.attempts.Load() == 0 || time.Since(started) > time.Second {
		t.Fatalf("adapter readiness ignored cancellation: %v", err)
	}
}

func TestAdapterReadinessStopsWhenGatewayExits(t *testing.T) {
	cap := &unavailableAdapter{Session: capture.NewFakeSession(capture.Info{})}
	gateway := tunnel.NewFakeSession(tunnel.Info{Up: true})
	_ = gateway.Close()
	started := time.Now()
	err := attachCaptureAdapter(context.Background(), cap, "fixture", gateway)
	if err == nil || !strings.Contains(err.Error(), "gateway exited") || time.Since(started) > time.Second {
		t.Fatalf("adapter wait ignored a dead gateway: %v", err)
	}
}

func TestAttachFailureIsJournaledWithGatewayLogClass(t *testing.T) {
	e, _ := networkTestEngine(t)
	e.cap = &unavailableAdapter{Session: capture.NewFakeSession(capture.Info{})}
	gateway := tunnel.NewFakeSession(tunnel.Info{Up: true, StderrClass: "tun_setup"})
	_ = gateway.Close()
	if err := e.attachLocked(gateway); err == nil {
		t.Fatal("attach unexpectedly succeeded")
	}
	history := eventsOf(diag.ReadFailures(), "engine")
	if len(history) != 1 || history[0].Event != "adapter_attach_failed" || history[0].Class != "gateway_exit" || history[0].Reason != "tun_setup" {
		t.Fatalf("attach evidence: %+v", history)
	}
}
