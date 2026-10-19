package engine

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/policy"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

type desyncHostCheck struct {
	*desync.FakeSession
	check func(string) desync.FailSignal
}

func (s *desyncHostCheck) ProbeTLS(host string) desync.FailSignal { return s.check(host) }

type tunnelHostCheck struct {
	*tunnel.FakeSession
	check func(string) tunnel.FailSignal
}

func (s *tunnelHostCheck) ProbeTLS(host string) tunnel.FailSignal { return s.check(host) }

// Reproduce the report without user data or live/privileged network changes:
// Discord works locally, IMVU resets, the provider failed, the fallback is up.
func unavailableIMVUEngine(t *testing.T) *Engine {
	t.Helper()
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	e := activeBackgroundEngine(t)
	e.state = StateDegraded
	e.targets = []ipc.TargetStatus{
		{ID: "discord", Label: "Discord", Path: policy.PathDesync, Outcome: "ok"},
		{ID: "imvu", Label: "IMVU", Path: policy.PathTunnel, Outcome: "retry"},
	}
	message := unavailablePathMessage(e.targets)
	e.pathError, e.lastError = &message, &message
	e.desyncConfig = &desync.Config{
		Context: e.sessionContextLocked(), ListenIP: "127.0.0.1", ListenPort: 18080,
		Strategy: desync.NativeSafeStrategy(), ConnIP: "192.0.2.10", BindInterface: "Wi-Fi",
		Resolve: func(context.Context, string) (netip.Addr, error) { return netip.MustParseAddr("192.0.2.1"), nil },
	}
	e.des = desync.NewFakeSession(desync.Info{LastProbe: desync.FailReset})
	e.tun = tunnel.NewFakeSession(tunnel.Info{ProviderID: tunnel.ProviderDesync, Up: true})
	e.policy.OnDesyncOK("discord.com", e.des.StrategyID())
	e.policy.OnDesyncFail(desync.FailSignal{Target: "secure.imvu.com", Class: desync.FailReset})
	var err error
	e.strategyStore, err = desync.OpenStrategyStore(t.TempDir() + "/strategies.json")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestStrategyRecoveryVerifiesBothTargetsAndCachesWinner(t *testing.T) {
	e := unavailableIMVUEngine(t)
	original := e.des.(*desync.FakeSession)
	winner := desync.NativeScanCandidates()[1]
	e.scanDesync = func(ctx context.Context, cfg desync.ScanConfig) desync.ScanResult {
		if original.Closed() || cfg.Host != "secure.imvu.com" || len(cfg.VerifyHosts) != 2 ||
			cfg.ConnIP != "192.0.2.10" || cfg.BindInterface != "Wi-Fi" || cfg.Resolve == nil {
			t.Fatalf("trial lost healthy helper, other target or egress: %+v", cfg)
		}
		if _, skip := cfg.SkipIDs[desync.NativeSafeStrategy().ID]; !skip {
			t.Fatal("failed strategy was not skipped")
		}
		return desync.ScanResult{OK: true, Strategy: winner, Reason: "ok"}
	}
	var checked []string
	e.startDesync = func(cfg desync.Config) (desync.Session, error) {
		if cfg.ProbeHost != "" || cfg.ListenPort != 18080 || cfg.Strategy.ID != winner.ID {
			t.Fatalf("real helper config: %+v", cfg)
		}
		return &desyncHostCheck{desync.NewFakeSession(desync.Info{StrategyID: winner.ID}), func(host string) desync.FailSignal {
			checked = append(checked, host)
			return desync.FailSignal{Target: host, Class: desync.FailOK}
		}}, nil
	}
	e.recoverDesyncStrategySession(e.sessionGeneration)
	if !original.Closed() || len(checked) != 2 || e.Status().State != StateActive || e.pathError != nil {
		t.Fatalf("winner not verified/adopted: checked=%v state=%+v", checked, e.Status())
	}
	for _, target := range e.targets {
		if target.Path != policy.PathDesync || target.Outcome != "ok" {
			t.Fatalf("target not recovered: %+v", target)
		}
	}
	if cached, ok := e.strategyStore.Lookup(e.policy.ASN()); !ok || cached.ID != winner.ID {
		t.Fatalf("winner not cached: %+v %v", cached, ok)
	}
	if e.desyncConfig.Strategy.ID != winner.ID {
		t.Fatal("process recovery would restore the old strategy")
	}
}

func TestStrategyRecoveryRollsBackWhenRealHelperBreaksDiscord(t *testing.T) {
	e := unavailableIMVUEngine(t)
	winner := desync.NativeScanCandidates()[1]
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		return desync.ScanResult{OK: true, Strategy: winner}
	}
	var rejected *desync.FakeSession
	var started []string
	e.startDesync = func(cfg desync.Config) (desync.Session, error) {
		started = append(started, cfg.Strategy.ID)
		if cfg.Strategy.ID == winner.ID {
			rejected = desync.NewFakeSession(desync.Info{StrategyID: winner.ID, LastProbe: desync.FailReset})
			return rejected, nil
		}
		return desync.NewFakeSession(desync.Info{StrategyID: cfg.Strategy.ID}), nil
	}
	e.recoverDesyncStrategySession(e.sessionGeneration)
	if len(started) != 2 || !rejected.Closed() || !e.des.Info().Up || e.des.StrategyID() != desync.NativeSafeStrategy().ID {
		t.Fatalf("failed winner not rolled back: starts=%v", started)
	}
	if e.Status().State != StateDegraded || e.pathError == nil || e.desyncScan.OK || e.desyncScan.Reason != "verification_failed" {
		t.Fatalf("scan success masked real failure: %+v", e.desyncScan)
	}
	if cached, ok := e.strategyStore.Lookup(e.policy.ASN()); ok {
		t.Fatalf("unverified winner cached: %+v", cached)
	}
	if path := e.policy.HintFor("secure.imvu.com"); path != policy.PathTunnel {
		t.Fatalf("failed verification changed policy: %s", path)
	}
}

func TestFailedStrategySearchRunsOnlyOncePerSession(t *testing.T) {
	e := unavailableIMVUEngine(t)
	calls := 0
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		calls++
		return desync.ScanResult{Reason: "exhausted"}
	}
	e.recoverDesyncStrategySession(e.sessionGeneration)
	e.recoverDesyncStrategySession(e.sessionGeneration)
	if calls != 1 || e.Status().State != StateDegraded {
		t.Fatalf("failed scan repeated or masked failure: calls=%d", calls)
	}
}

func TestRecoveredDataplaneCanSchedulePreviouslyUnavailableScan(t *testing.T) {
	e := unavailableIMVUEngine(t)
	_ = e.tun.Close()
	e.tunnelConfig = &tunnel.Config{AllowlistOutbound: "desync"}
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) {
		return tunnel.NewFakeSession(tunnel.Info{ProviderID: tunnel.ProviderDesync, Up: true}), nil
	}
	scanned := make(chan struct{})
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		close(scanned)
		return desync.ScanResult{Reason: "exhausted"}
	}
	e.recoverComponent(e.sessionGeneration, time.Now())
	awaitBackground(t, scanned)
	if e.Status().State != StateDegraded || e.pathError == nil {
		t.Fatal("process restart was mistaken for protected-path recovery")
	}
}

func TestStrategyScanDoesNotBlockStatusOrStopAndDiscardsLateResult(t *testing.T) {
	e := unavailableIMVUEngine(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		close(entered)
		<-release // Simulate a dependency that ignores cancellation.
		return desync.ScanResult{OK: true, Strategy: desync.NativeScanCandidates()[1]}
	}
	starts := 0
	e.startDesync = func(desync.Config) (desync.Session, error) { starts++; return nil, nil }
	generation := e.sessionGeneration
	go func() { defer close(done); e.recoverDesyncStrategySession(generation) }()
	finish := sync.OnceFunc(func() { close(release); <-done })
	defer finish()
	awaitBackground(t, entered)
	if st := e.Status(); st.State != StateDegraded {
		t.Fatalf("status unavailable during scan: %+v", st)
	}
	if _, err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	marker := &desync.ScanResult{Reason: "next-session"}
	e.mu.Lock()
	e.desyncScan = marker
	e.mu.Unlock()
	finish()
	if starts != 0 || e.Status().State != StateStopped || e.desyncScan != marker {
		t.Fatal("old scan changed the stopped/new session")
	}
}

func TestStrategyVerificationDoesNotBlockStopOrAdoptLateHelper(t *testing.T) {
	e := unavailableIMVUEngine(t)
	winner := desync.NativeScanCandidates()[1]
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		return desync.ScanResult{OK: true, Strategy: winner}
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	trial := desync.NewFakeSession(desync.Info{StrategyID: winner.ID})
	var once sync.Once
	e.startDesync = func(desync.Config) (desync.Session, error) {
		return &desyncHostCheck{trial, func(host string) desync.FailSignal {
			once.Do(func() { close(entered) })
			<-release // A late verified helper must still belong to this session.
			return desync.FailSignal{Target: host, Class: desync.FailOK}
		}}, nil
	}
	generation := e.sessionGeneration
	go func() { defer close(done); e.recoverDesyncStrategySession(generation) }()
	finish := sync.OnceFunc(func() { close(release); <-done })
	defer finish()
	awaitBackground(t, entered)
	if _, err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	finish()
	if !trial.Closed() || e.Status().State != StateStopped || e.des != nil {
		t.Fatal("late verified helper outlived Stop")
	}
}

func TestProtectedPathRetriesAfterFailureAndRecoversWithoutRestart(t *testing.T) {
	e := unavailableIMVUEngine(t)
	calls := 0
	e.tun = &tunnelHostCheck{e.tun.(*tunnel.FakeSession), func(host string) tunnel.FailSignal {
		calls++
		class := tunnel.FailOK
		if calls == 1 {
			class = tunnel.FailTimeout
		}
		return tunnel.FailSignal{Target: host, Class: class}
	}}
	now := time.Now()
	e.recoverProtectedPath(e.sessionGeneration, now)
	if e.pathError == nil || e.Status().State != StateDegraded {
		t.Fatal("failed TLS check reported healthy")
	}
	e.recoverProtectedPath(e.sessionGeneration, now.Add(time.Second))
	if calls != 1 {
		t.Fatal("path retries ignored the cooldown")
	}
	e.recoverProtectedPath(e.sessionGeneration, now.Add(pathCheckInterval))
	if calls != 2 || e.Status().State != StateActive || e.pathError != nil {
		t.Fatalf("working path remained degraded: calls=%d status=%+v", calls, e.Status())
	}
}

func TestProtectedPathRecoveryKeepsIndependentCanaryFailure(t *testing.T) {
	e := unavailableIMVUEngine(t)
	e.policy.Put("www.youtube.com", policy.PathTunnel, "ip_drop", "test")
	e.recoverProtectedPath(e.sessionGeneration, time.Now())
	if e.pathError == nil || e.Status().State != StateDegraded {
		t.Fatal("IMVU recovery cleared an independent canary failure")
	}
}

func TestProtectedPathCheckDiscardsPreviousSession(t *testing.T) {
	e := unavailableIMVUEngine(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.tun = &tunnelHostCheck{e.tun.(*tunnel.FakeSession), func(host string) tunnel.FailSignal {
		close(entered)
		<-release
		return tunnel.FailSignal{Target: host, Class: tunnel.FailOK}
	}}
	go func() { defer close(done); e.recoverProtectedPath(e.sessionGeneration, time.Now()) }()
	finish := sync.OnceFunc(func() { close(release); <-done })
	defer finish()
	awaitBackground(t, entered)
	replaceBackgroundSession(e)
	finish()
	if e.pathError == nil || e.policy.HintFor("secure.imvu.com") != "" {
		t.Fatal("old path check changed the new session")
	}
}
