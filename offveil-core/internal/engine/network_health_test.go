package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

var testControls = []string{"control-a.test", "control-b.test", "control-c.test"}

type tunnelHostCheck struct {
	*tunnel.FakeSession
	check func(string) tunnel.FailSignal
}

func (s *tunnelHostCheck) ProbeTLS(host string) tunnel.FailSignal { return s.check(host) }

type healthSession struct {
	*tunnel.FakeSession
	health  func(context.Context) bool
	refresh func(context.Context) error
}

func (s *healthSession) CheckHealth(ctx context.Context) bool { return s.health(ctx) }
func (s *healthSession) RefreshTransport(ctx context.Context) error {
	if s.refresh == nil {
		return errors.New("no remote transport")
	}
	return s.refresh(ctx)
}

func networkTestEngine(t *testing.T, mode string) *Engine {
	t.Helper()
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	e := activeBackgroundEngine(t)
	e.extraProbeHosts = append([]string(nil), testControls...)
	provider := tunnel.ProviderWARP
	if mode == "local" {
		provider = tunnel.ProviderDesync
	}
	e.tun = tunnel.NewFakeSession(tunnel.Info{Up: true, Healthy: true, Mode: mode, ProviderID: provider})
	e.des = desync.NewFakeSession(desync.Info{Up: true, StrategyID: desync.NativeSafeStrategy().ID})
	e.tunnelConfig = &tunnel.Config{NetworkMode: true, Context: e.sessionContextLocked()}
	e.desyncConfig = &desync.Config{Context: e.sessionContextLocked(), ListenIP: "127.0.0.1", ListenPort: 18080, Strategy: desync.NativeSafeStrategy()}
	e.lastTransportRetry = time.Now()
	e.cleanup.Register("desync", func() error {
		if e.des != nil {
			return e.des.Close()
		}
		return nil
	})
	e.cleanup.Register("network", func() error {
		if e.tun != nil {
			return e.tun.Close()
		}
		return nil
	})
	e.refreshNetworkStatusLocked()
	return e
}

func TestSingleUnavailableEndpointDoesNotGateNetworkControls(t *testing.T) {
	e := networkTestEngine(t, "remote")
	e.lastProbe = &probe.Report{Results: []probe.Result{{Target: "unrelated.test", Class: probe.ClassDPIReset}}}
	var checks atomic.Int32
	e.tun = &tunnelHostCheck{e.tun.(*tunnel.FakeSession), func(host string) tunnel.FailSignal {
		checks.Add(1)
		class := tunnel.FailOK
		if host == testControls[0] {
			class = tunnel.FailReset
		}
		return tunnel.FailSignal{Target: host, Class: class}
	}}
	e.checkNetworkSession(e.sessionGeneration, time.Now())
	st := e.Status()
	if checks.Load() != 3 || st.State != StateActive || !e.networkCheck.Healthy || st.LastError != nil {
		t.Fatalf("one target suppressed healthy transport: checks=%d status=%+v network=%+v", checks.Load(), st, e.networkCheck)
	}
}

func TestRepeatedControlQuorumFailureAndRecovery(t *testing.T) {
	e := networkTestEngine(t, "remote")
	var healthy atomic.Bool
	e.tun = &healthSession{FakeSession: e.tun.(*tunnel.FakeSession), health: func(context.Context) bool { return healthy.Load() }}
	now := time.Now()
	e.checkNetworkSession(e.sessionGeneration, now)
	if e.Status().State != StateActive {
		t.Fatal("a transient control round replaced the accepted transport")
	}
	e.checkNetworkSession(e.sessionGeneration, now.Add(networkCheckInterval))
	if e.Status().State != StateDegraded || e.networkCheck.Reason != "control_quorum_failed" {
		t.Fatal("repeated failure hidden")
	}
	healthy.Store(true)
	e.checkNetworkSession(e.sessionGeneration, now.Add(2*networkCheckInterval))
	if st := e.Status(); st.State != StateActive || st.LastError != nil || !e.networkCheck.Healthy {
		t.Fatalf("quorum recovery lost: %+v", st)
	}
}

func TestLocalCoverageNeverBecomesFullProtectionFromTLS(t *testing.T) {
	e := networkTestEngine(t, "local")
	e.checkNetworkSession(e.sessionGeneration, time.Now())
	st := e.Status()
	if st.State != StateDegraded || st.Summary != "Sınırlı koruma" || st.LastError != nil || e.networkCheck.Coverage != "tls_http_only" || e.networkCheck.UDPPath != "direct" {
		t.Fatalf("local TLS health overstated opaque TCP/UDP coverage: %+v %+v", st, e.networkCheck)
	}
}

func TestNetworkChecksDiscardReplacementSessionResults(t *testing.T) {
	e := networkTestEngine(t, "remote")
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.tun = &healthSession{FakeSession: e.tun.(*tunnel.FakeSession), health: func(context.Context) bool { close(entered); <-release; return false }}
	generation := e.sessionGeneration
	go func() { defer close(done); e.checkNetworkSession(generation, time.Now()) }()
	awaitBackground(t, entered)
	replaceBackgroundSession(e)
	close(release)
	awaitBackground(t, done)
	if e.networkCheck != nil || e.networkFailures != 0 {
		t.Fatal("old health result reached a replacement session")
	}
}

func TestSessionCancellationStopsNetworkChecks(t *testing.T) {
	e := networkTestEngine(t, "remote")
	entered, done := make(chan struct{}), make(chan struct{})
	e.tun = &healthSession{FakeSession: e.tun.(*tunnel.FakeSession), health: func(ctx context.Context) bool { close(entered); <-ctx.Done(); return false }}
	go func() { defer close(done); e.checkNetworkSession(e.sessionGeneration, time.Now()) }()
	awaitBackground(t, entered)
	if _, err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	awaitBackground(t, done)
}

func TestTransportRefreshDoesNotBlockStopOrAdoptLateWork(t *testing.T) {
	e := networkTestEngine(t, "local")
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	session := &healthSession{FakeSession: e.tun.(*tunnel.FakeSession), health: func(context.Context) bool { return true }, refresh: func(context.Context) error { once.Do(func() { close(entered) }); <-release; return nil }}
	e.tun = session
	generation := e.sessionGeneration
	go func() { defer close(done); e.refreshTransportSession(generation, session) }()
	awaitBackground(t, entered)
	stopped := make(chan struct{})
	go func() { defer close(stopped); _, _ = e.Stop() }()
	awaitBackground(t, stopped)
	close(release)
	awaitBackground(t, done)
	if st := e.Status(); st.Protection || st.State != StateStopped || !session.Closed() {
		t.Fatalf("late transport restored stopped protection: %+v", st)
	}
}

func TestRetainedActiveSnapshotReportsCurrentProtectionOff(t *testing.T) {
	e := networkTestEngine(t, "remote")
	e.freezeSupportLocked()
	e.protection, e.state = false, StateStopped
	in := e.diagnosticsInputLocked()
	if !in.Cascade.Protection || in.System["protection_state"] != "off" || e.lastSupport.System["protection_state"] != "on" {
		t.Fatal("retained snapshot mutated or misreported current protection")
	}
}
