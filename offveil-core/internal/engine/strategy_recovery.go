package engine

import (
	"sync"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func (e *Engine) strategyScopeLocked() string {
	return "network-v3|" + e.policy.ASN() + "|" + e.policy.Fingerprint() + "|tls"
}

func helperControlQuorum(session desync.Session, hosts []string) bool {
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for _, host := range hosts {
		wg.Go(func() {
			if session.ProbeTLS(host).Class == desync.FailOK {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return len(hosts) >= 2 && passed >= 2
}

// scanCandidatesLocked merges built-in candidates with signed ruleset ones.
func (e *Engine) scanCandidatesLocked() []desync.Strategy {
	var extra []desync.Strategy
	if e.rulesetSnap != nil {
		var errs []error
		extra, errs = desync.CandidatesFrom(e.rulesetSnap.Doc.Strategies)
		for _, err := range errs {
			e.recordFailureLocked(diag.Failure{Component: "desync", Event: "strategy_rejected", Reason: diag.Scrub(err.Error())})
		}
	}
	return desync.MergeCandidates(desync.NativeScanCandidates(), extra)
}

// recoverDesyncStrategySession searches for a strategy that opens the failing
// group's canary without breaking neutral controls. A strategy is adopted
// only after the real helper and the gateway open that canary too.
func (e *Engine) recoverDesyncStrategySession(generation uint64, groupID string) {
	e.mu.Lock()
	g := e.groupLocked(groupID)
	if !e.currentSessionLocked(generation) || g == nil || e.strategySwitching || e.layer != layerSelective || e.desyncScan != nil ||
		e.desyncConfig == nil || e.des == nil || e.tun == nil || !e.tun.Info().Up {
		e.groupWork = false
		e.mu.Unlock()
		return
	}
	hosts := e.controlHostsLocked()
	target := g.Hosts[0]
	original, dataplane, cfg := e.des, e.tun, *e.desyncConfig
	ctx, start, scan := e.sessionContextLocked(), e.startDesync, e.scanDesync
	if start == nil {
		start = desync.Start
	}
	if scan == nil {
		scan = desync.Scan
	}
	candidates := e.scanCandidatesLocked()
	pending := &desync.ScanResult{Reason: "running"}
	e.desyncScan = pending
	e.publishOperationLocked("desync_scan")
	e.mu.Unlock()
	result := scan(ctx, desync.ScanConfig{
		Required: []string{target}, VerifyHosts: hosts, VerifyQuorum: 2, PassThroughFirst: true, Candidates: candidates,
		Timeout: desync.ScanEnvTimeout(), SkipIDs: map[string]struct{}{desync.BaseID(cfg.Strategy.ID): {}},
		Start: desync.StartFunc(start), Resolve: cfg.Resolve, AssignJob: cfg.AssignJob,
		BinaryPath: cfg.BinaryPath, ConnIP: cfg.ConnIP, BindInterface: cfg.BindInterface,
	})
	e.mu.Lock()
	finish := func() {
		e.groupWork = false
		e.publishOperationLocked("")
		e.mu.Unlock()
	}
	if !e.currentSessionLocked(generation) || e.desyncScan != pending {
		finish()
		return
	}
	if ctx.Err() != nil || e.des != original || e.tun != dataplane || e.strategySwitching || e.layer != layerSelective {
		e.desyncScan = nil
		finish()
		return
	}
	e.desyncScan = &result
	for _, tried := range result.Tried {
		e.recordFailureLocked(diag.Failure{Component: "desync", Event: "strategy_trial", Strategy: tried.StrategyID, Reason: string(tried.Class), Target: groupID})
	}
	e.recordFailureLocked(diag.Failure{Component: "desync", Event: "strategy_scan", Reason: result.Reason, Target: groupID})
	if !result.OK || !desync.UsableOnOS(result.Strategy) || len(result.Strategy.Args) == 0 {
		// Leave the group failing; the next round escalates it to the tunnel.
		g.Failures = groupFailureThreshold
		e.desyncScan = nil
		finish()
		return
	}
	e.strategySwitching = true
	e.publishOperationLocked("desync_verify")
	if err := original.Close(); err != nil {
		e.desyncScan.OK, e.desyncScan.Reason, e.strategySwitching = false, "cleanup_failed", false
		finish()
		return
	}
	e.des = nil
	winner := cfg
	winner.Strategy, winner.ProbeHost, winner.ProbeTimeout = result.Strategy, "", desync.ScanPerStrategyTimeout
	e.mu.Unlock()
	next, err := start(winner)
	verified := err == nil && next != nil && next.Info().Up && ctx.Err() == nil
	if verified {
		verified = next.ProbeTLS(target).Class == desync.FailOK && helperControlQuorum(next, hosts) &&
			dataplane.ProbeTLS(target).Class == tunnel.FailOK
	}
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || ctx.Err() != nil || e.tun != dataplane {
		e.groupWork, e.strategySwitching = false, false
		e.mu.Unlock()
		if next != nil {
			_ = next.Close()
		}
		return
	}
	if verified {
		e.des, e.desyncConfig = next, &winner
		info := next.Info()
		e.desyncInfo = &info
		if e.strategyStore != nil {
			_ = e.strategyStore.Put(e.strategyScopeLocked(), strategyForCache(winner.Strategy), "canary:"+groupID)
		}
		g.OK, g.Failures, g.Unreachable = true, 0, false
		e.strategySwitching, e.desyncScan = false, nil
		e.recordFailureLocked(diag.Failure{Component: "desync", Event: "strategy_recovered", Strategy: winner.Strategy.ID, Target: groupID})
		e.refreshNetworkStatusLocked()
		finish()
		return
	}
	if next != nil {
		_ = next.Close()
	}
	e.desyncScan.OK, e.desyncScan.Reason = false, "verification_failed"
	cfg.ProbeHost = ""
	e.mu.Unlock()
	restored, restoreErr := start(cfg)
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || ctx.Err() != nil || e.tun != dataplane {
		e.groupWork, e.strategySwitching = false, false
		e.mu.Unlock()
		if restored != nil {
			_ = restored.Close()
		}
		return
	}
	e.des, e.strategySwitching = restored, false
	if restored != nil {
		info := restored.Info()
		e.desyncInfo = &info
	}
	if restoreErr != nil {
		e.recordFailureLocked(diag.Failure{Component: "desync", Event: "rollback_failed"})
	}
	g.Failures, e.desyncScan = groupFailureThreshold, nil
	e.refreshNetworkStatusLocked()
	finish()
}

// strategyForCache stores the candidate itself; startup re-applies the
// pass-through-first wrapper.
func strategyForCache(s desync.Strategy) desync.Strategy {
	if !desync.IsPassThrough(s) {
		return s
	}
	for i, arg := range s.Args {
		if arg == "--auto" && i+1 < len(s.Args) && s.Args[i+1] == "torst,ssl_err" {
			args := append(append([]string(nil), s.Args[:i]...), s.Args[i+2:]...)
			return desync.Strategy{ID: desync.BaseID(s.ID), Args: args, Note: s.Note}
		}
	}
	return s
}
