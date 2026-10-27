package engine

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

type desyncHostCheck struct {
	*desync.FakeSession
	check func(string) desync.FailSignal
}

func (s *desyncHostCheck) ProbeTLS(host string) desync.FailSignal { return s.check(host) }

func localRecoveryEngine(t *testing.T) (*Engine, *gatewayFixture) {
	t.Helper()
	e, gateway := networkTestEngine(t)
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
	return e, gateway
}

func TestStrategyRecoveryTargetsCanaryAndCachesBaseStrategy(t *testing.T) {
	e, gateway := localRecoveryEngine(t)
	original := e.des.(*desync.FakeSession)
	winner := desync.PassThroughFirst(desync.NativeScanCandidates()[1])
	e.scanDesync = func(_ context.Context, cfg desync.ScanConfig) desync.ScanResult {
		if original.Closed() || cfg.VerifyQuorum != 2 || len(cfg.VerifyHosts) != 3 || len(cfg.Required) != 1 || cfg.Required[0] != "chat.test" || !cfg.PassThroughFirst {
			t.Fatalf("invalid trial: %+v", cfg)
		}
		if _, skip := cfg.SkipIDs[desync.NativeSafeStrategy().ID]; !skip {
			t.Fatalf("current strategy not skipped: %+v", cfg.SkipIDs)
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
	e.groupLocked("chat").Failures = 2
	e.recoverDesyncStrategySession(e.sessionGeneration, "chat")
	if !original.Closed() || checked.Load() != 4 || gateway.Closed() || e.desyncConfig.Strategy.ID != winner.ID {
		t.Fatalf("winner not verified/adopted: checked=%d", checked.Load())
	}
	if g := e.groupLocked("chat"); !g.OK || g.Failures != 0 || e.groupWork {
		t.Fatalf("group: %+v", g)
	}
	cached, ok := e.strategyStore.Lookup(e.strategyScopeLocked())
	if !ok || cached.ID != desync.BaseID(winner.ID) || desync.IsPassThrough(cached) {
		t.Fatalf("cache must hold the bare candidate: %+v", cached)
	}
	if desync.PassThroughFirst(cached).ID != winner.ID {
		t.Fatal("cached strategy does not rebuild the deployed chain")
	}
}

func TestStrategyRecoveryRollsBackWhenGatewayStillFails(t *testing.T) {
	e, gateway := localRecoveryEngine(t)
	gateway.set("chat.test", tunnel.FailReset)
	original := e.desyncConfig.Strategy
	winner := desync.NativeScanCandidates()[1]
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		return desync.ScanResult{OK: true, Strategy: winner}
	}
	var starts atomic.Int32
	var rejected *desync.FakeSession
	e.startDesync = func(cfg desync.Config) (desync.Session, error) {
		starts.Add(1)
		f := desync.NewFakeSession(desync.Info{Up: true, StrategyID: cfg.Strategy.ID})
		if cfg.Strategy.ID == winner.ID {
			rejected = f
		}
		return f, nil
	}
	e.recoverDesyncStrategySession(e.sessionGeneration, "chat")
	if starts.Load() != 2 || rejected == nil || !rejected.Closed() || e.des.StrategyID() != original.ID || e.desyncScan != nil {
		t.Fatal("candidate that the gateway could not use replaced the accepted helper")
	}
	if g := e.groupLocked("chat"); g.Failures != groupFailureThreshold || e.groupWork {
		t.Fatalf("failed recovery must hand the group to escalation: %+v", g)
	}
}

func TestRulesetCandidatesJoinTheScan(t *testing.T) {
	e, _ := localRecoveryEngine(t)
	var got []desync.Strategy
	e.scanDesync = func(_ context.Context, cfg desync.ScanConfig) desync.ScanResult {
		got = cfg.Candidates
		return desync.ScanResult{Reason: "exhausted"}
	}
	snap := *e.rulesetSnap
	snap.Doc.Strategies = append(snap.Doc.Strategies,
		ruleset.StrategySpec{ID: "extra:split", Args: []string{"--split", "2"}},
		ruleset.StrategySpec{ID: "extra:bad", Args: []string{"--ip", "0.0.0.0"}})
	e.rulesetSnap = &snap
	e.recoverDesyncStrategySession(e.sessionGeneration, "chat")
	found := false
	for _, s := range got {
		if s.ID == "extra:split" {
			found = true
		}
		if s.ID == "extra:bad" {
			t.Fatal("unsafe ruleset strategy reached the scan")
		}
	}
	if !found || len(got) <= len(desync.NativeScanCandidates()) {
		t.Fatalf("candidates: %d", len(got))
	}
}

func TestStrategyScanDoesNotBlockStatusOrStopAndDiscardsLateResult(t *testing.T) {
	e, _ := localRecoveryEngine(t)
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
	go func() { defer close(done); e.recoverDesyncStrategySession(generation, "chat") }()
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

func TestPendingScanOwnershipClearsWhenHelperChanges(t *testing.T) {
	e, _ := localRecoveryEngine(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		close(entered)
		<-release
		return desync.ScanResult{Reason: "exhausted"}
	}
	generation := e.sessionGeneration
	go func() { defer close(done); e.recoverDesyncStrategySession(generation, "chat") }()
	awaitBackground(t, entered)
	e.mu.Lock()
	e.des = desync.NewFakeSession(desync.Info{Up: true})
	e.mu.Unlock()
	close(release)
	awaitBackground(t, done)
	if e.desyncScan != nil || e.groupWork {
		t.Fatal("superseded scan left a permanent running marker")
	}
}
