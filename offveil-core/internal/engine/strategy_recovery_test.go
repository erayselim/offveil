package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

type desyncHostCheck struct {
	*desync.FakeSession
	check func(string) desync.FailSignal
}

func (s *desyncHostCheck) ProbeTLS(host string) desync.FailSignal { return s.check(host) }

func localRecoveryEngine(t *testing.T) *Engine {
	t.Helper()
	e := networkTestEngine(t, "local")
	var err error
	e.strategyStore, err = desync.OpenStrategyStore(t.TempDir() + "/strategies.json")
	if err != nil {
		t.Fatal(err)
	}
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		return desync.ScanResult{Reason: "exhausted"}
	}
	e.startDesync = func(cfg desync.Config) (desync.Session, error) {
		return desync.NewFakeSession(desync.Info{Up: true, StrategyID: cfg.Strategy.ID}), nil
	}
	return e
}

func TestStrategyRecoveryUsesIndependentQuorumAndScopedCache(t *testing.T) {
	e := localRecoveryEngine(t)
	original := e.des.(*desync.FakeSession)
	gateway := e.tun.(*tunnel.FakeSession)
	winner := desync.NativeScanCandidates()[1]
	e.scanDesync = func(_ context.Context, cfg desync.ScanConfig) desync.ScanResult {
		if original.Closed() || cfg.VerifyQuorum != 2 || len(cfg.VerifyHosts) != 3 {
			t.Fatalf("invalid non-destructive trial: %+v", cfg)
		}
		return desync.ScanResult{OK: true, Strategy: winner, Reason: "ok"}
	}
	var checked atomic.Int32
	e.startDesync = func(cfg desync.Config) (desync.Session, error) {
		if cfg.ProbeHost != "" || cfg.ListenPort != 18080 {
			t.Fatalf("unexpected adoption config: %+v", cfg)
		}
		return &desyncHostCheck{desync.NewFakeSession(desync.Info{Up: true, StrategyID: cfg.Strategy.ID}), func(host string) desync.FailSignal {
			checked.Add(1)
			class := desync.FailOK
			if host == testControls[0] {
				class = desync.FailReset
			}
			return desync.FailSignal{Target: host, Class: class}
		}}, nil
	}
	e.recoverDesyncStrategySession(e.sessionGeneration)
	if !original.Closed() || checked.Load() != 3 || gateway.Closed() || e.desyncConfig.Strategy.ID != winner.ID {
		t.Fatal("winner not independently verified/adopted")
	}
	if e.Status().Summary != "Sınırlı koruma" {
		t.Fatal("TLS success conferred full network coverage")
	}
	if cached, ok := e.strategyStore.Lookup(e.strategyScopeLocked()); !ok || cached.ID != winner.ID {
		t.Fatal("network-scoped strategy not stored")
	}
	if _, ok := e.strategyStore.Lookup(e.policy.ASN()); ok {
		t.Fatal("network evidence escaped into the old ASN-only cache")
	}
}

func TestStrategyRecoveryRollsBackFailedRealPortVerification(t *testing.T) {
	e := localRecoveryEngine(t)
	original := e.desyncConfig.Strategy
	winner := desync.NativeScanCandidates()[1]
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		return desync.ScanResult{OK: true, Strategy: winner}
	}
	var rejected *desync.FakeSession
	var starts atomic.Int32
	e.startDesync = func(cfg desync.Config) (desync.Session, error) {
		starts.Add(1)
		f := desync.NewFakeSession(desync.Info{Up: true, StrategyID: cfg.Strategy.ID})
		if cfg.Strategy.ID == winner.ID {
			rejected = f
			return &desyncHostCheck{f, func(host string) desync.FailSignal { return desync.FailSignal{Target: host, Class: desync.FailReset} }}, nil
		}
		return f, nil
	}
	e.recoverDesyncStrategySession(e.sessionGeneration)
	if starts.Load() != 2 || rejected == nil || !rejected.Closed() || e.des.StrategyID() != original.ID || e.desyncScan.Reason != "verification_failed" {
		t.Fatal("failed real-port candidate replaced accepted helper")
	}
}

func TestFailedStrategySearchIsBoundedPerSession(t *testing.T) {
	e := localRecoveryEngine(t)
	var scans atomic.Int32
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		scans.Add(1)
		return desync.ScanResult{Reason: "exhausted"}
	}
	e.recoverDesyncStrategySession(e.sessionGeneration)
	e.recoverDesyncStrategySession(e.sessionGeneration)
	if scans.Load() != 1 {
		t.Fatal("failed discovery loops without a new episode")
	}
}

func TestPendingScanOwnershipClearsWhenHelperChanges(t *testing.T) {
	e := localRecoveryEngine(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		close(entered)
		<-release
		return desync.ScanResult{Reason: "exhausted"}
	}
	generation := e.sessionGeneration
	go func() { defer close(done); e.recoverDesyncStrategySession(generation) }()
	awaitBackground(t, entered)
	e.mu.Lock()
	e.des = desync.NewFakeSession(desync.Info{Up: true})
	e.mu.Unlock()
	close(release)
	awaitBackground(t, done)
	if e.desyncScan != nil {
		t.Fatal("superseded scan left a permanent running marker")
	}
}

func TestStrategyScanDoesNotBlockStatusOrStopAndDiscardsLateResult(t *testing.T) {
	e := localRecoveryEngine(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		close(entered)
		<-release
		return desync.ScanResult{OK: true, Strategy: desync.NativeScanCandidates()[1]}
	}
	var starts atomic.Int32
	e.startDesync = func(desync.Config) (desync.Session, error) {
		starts.Add(1)
		return desync.NewFakeSession(desync.Info{Up: true}), nil
	}
	generation := e.sessionGeneration
	go func() { defer close(done); e.recoverDesyncStrategySession(generation) }()
	awaitBackground(t, entered)
	stopped := make(chan struct{})
	go func() { _ = e.Status(); _, _ = e.Stop(); close(stopped) }()
	awaitBackground(t, stopped)
	close(release)
	awaitBackground(t, done)
	if starts.Load() != 0 || e.Status().Protection {
		t.Fatal("stale scan started a helper after Stop")
	}
}

func TestStrategyVerificationDiscardsLateHelperAfterStop(t *testing.T) {
	e := localRecoveryEngine(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		return desync.ScanResult{OK: true, Strategy: desync.NativeScanCandidates()[1]}
	}
	late := desync.NewFakeSession(desync.Info{Up: true})
	e.startDesync = func(desync.Config) (desync.Session, error) { close(entered); <-release; return late, nil }
	generation := e.sessionGeneration
	go func() { defer close(done); e.recoverDesyncStrategySession(generation) }()
	awaitBackground(t, entered)
	_, _ = e.Stop()
	close(release)
	awaitBackground(t, done)
	if !late.Closed() || e.Status().Protection {
		t.Fatal("late verified helper survived Stop")
	}
}

func TestStrategyScanCannotReplaceRemotePromotion(t *testing.T) {
	e := localRecoveryEngine(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		close(entered)
		<-release
		return desync.ScanResult{OK: true, Strategy: desync.NativeScanCandidates()[1]}
	}
	generation := e.sessionGeneration
	go func() { defer close(done); e.recoverDesyncStrategySession(generation) }()
	awaitBackground(t, entered)
	e.mu.Lock()
	info := tunnel.Info{Up: true, Mode: "remote", Healthy: true, ProviderID: tunnel.ProviderWARP}
	e.tun = tunnel.NewFakeSession(info)
	e.tunnelInfo = &info
	e.mu.Unlock()
	close(release)
	awaitBackground(t, done)
	if e.desyncScan != nil || e.strategySwitching {
		t.Fatal("local scan took ownership of a remote transport")
	}
}

func TestControlRetryRetainsLocalCoverage(t *testing.T) {
	e := localRecoveryEngine(t)
	e.networkFailures = 2
	e.lastPathCheck = time.Now().Add(-networkCheckInterval)
	e.checkNetworkSession(e.sessionGeneration, time.Now())
	if e.Status().Summary != "Sınırlı koruma" || e.networkCheck.Coverage != "tls_http_only" {
		t.Fatal("successful TLS controls overstated fallback coverage")
	}
}
