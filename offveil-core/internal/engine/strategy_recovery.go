package engine

import (
	"sync"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
)

func (e *Engine) strategyScopeLocked() string {
	return "network-v2|" + e.policy.ASN() + "|" + e.policy.Fingerprint() + "|tls"
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

// Discovery repairs only the local TLS/HTTP fallback. It cannot confer opaque
// TCP/UDP tunnel coverage, and one failed control cannot veto the quorum.
func (e *Engine) recoverDesyncStrategySession(generation uint64) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.strategySwitching || e.networkModeLocked() != "local" || e.desyncScan != nil || e.desyncConfig == nil || e.des == nil || e.tun == nil || !e.tun.Info().Up {
		e.mu.Unlock()
		return
	}
	hosts := e.controlHostsLocked()
	if len(hosts) < 2 {
		e.mu.Unlock()
		return
	}
	original, dataplane, cfg := e.des, e.tun, *e.desyncConfig
	ctx, start, scan := e.sessionContextLocked(), e.startDesync, e.scanDesync
	if start == nil {
		start = desync.Start
	}
	if scan == nil {
		scan = desync.Scan
	}
	pending := &desync.ScanResult{Reason: "running"}
	e.desyncScan = pending
	e.publishOperationLocked("desync_scan")
	e.mu.Unlock()
	result := scan(ctx, desync.ScanConfig{
		Host: hosts[0], VerifyHosts: hosts, VerifyQuorum: 2,
		Timeout: desync.ScanEnvTimeout(), SkipIDs: map[string]struct{}{cfg.Strategy.ID: {}},
		Start: desync.StartFunc(start), Resolve: cfg.Resolve, AssignJob: cfg.AssignJob,
		BinaryPath: cfg.BinaryPath, ConnIP: cfg.ConnIP, BindInterface: cfg.BindInterface,
	})
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.desyncScan != pending {
		e.mu.Unlock()
		return
	}
	if ctx.Err() != nil || e.des != original || e.tun != dataplane || e.strategySwitching || e.networkModeLocked() != "local" {
		e.desyncScan = nil
		e.publishOperationLocked("")
		e.mu.Unlock()
		return
	}
	e.desyncScan = &result
	for _, tried := range result.Tried {
		e.recordFailureLocked(diag.Failure{Component: "desync", Event: "strategy_trial", Strategy: tried.StrategyID, Reason: string(tried.Class)})
	}
	e.recordFailureLocked(diag.Failure{Component: "desync", Event: "strategy_scan", Reason: result.Reason})
	if !result.OK || !desync.UsableOnOS(result.Strategy) || len(result.Strategy.Args) == 0 {
		e.publishOperationLocked("")
		e.mu.Unlock()
		return
	}
	e.strategySwitching = true
	e.publishOperationLocked("desync_verify")
	if err := original.Close(); err != nil {
		e.desyncScan.OK, e.desyncScan.Reason, e.strategySwitching = false, "cleanup_failed", false
		e.publishOperationLocked("")
		e.mu.Unlock()
		return
	}
	e.des = nil
	winner := cfg
	winner.Strategy, winner.ProbeHost, winner.ProbeTimeout = result.Strategy, "", desync.ScanPerStrategyTimeout
	e.mu.Unlock()
	next, err := start(winner)
	verified := err == nil && next != nil && next.Info().Up && ctx.Err() == nil
	if verified {
		verified = helperControlQuorum(next, hosts) && probeControlQuorum(dataplane, hosts)
	}
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || ctx.Err() != nil || e.tun != dataplane {
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
			_ = e.strategyStore.Put(e.strategyScopeLocked(), winner.Strategy, "control_quorum")
		}
		e.strategySwitching, e.networkFailures = false, 0
		e.networkCheck = &NetworkHealth{Healthy: true, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
		e.refreshNetworkStatusLocked()
		e.recordFailureLocked(diag.Failure{Component: "desync", Event: "strategy_recovered"})
		e.publishOperationLocked("")
		e.mu.Unlock()
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
	defer e.mu.Unlock()
	if !e.currentSessionLocked(generation) || ctx.Err() != nil || e.tun != dataplane {
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
	e.refreshNetworkStatusLocked()
	e.publishOperationLocked("")
}
