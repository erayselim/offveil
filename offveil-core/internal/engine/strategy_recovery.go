package engine

import (
	"log/slog"
	"strings"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/policy"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

// recoverDesyncStrategySession runs only after tunnel providers were exhausted.
// Trials use private SOCKS ports and the same physical egress as the live helper.
// No policy changes until the winner also passes on the real helper port.
func (e *Engine) recoverDesyncStrategySession(generation uint64) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.pathError == nil || e.desyncScan != nil ||
		e.desyncConfig == nil || e.des == nil || e.rulesetSnap == nil ||
		e.tun == nil || e.tun.ProviderID() != tunnel.ProviderDesync || !e.tun.Info().Up {
		e.mu.Unlock()
		return
	}
	hosts := e.rulesetSnap.Doc.ProbeHosts()
	failedHost := ""
	for _, host := range hosts {
		if targetPath(e.targets, e.rulesetSnap.Doc.PackageIDForHost(host)) == policy.PathTunnel {
			failedHost = host
			break
		}
	}
	if failedHost == "" {
		e.mu.Unlock()
		return
	}
	cfg := *e.desyncConfig
	original := e.des
	ctx := e.sessionContextLocked()
	start := e.startDesync
	scan := e.scanDesync
	if scan == nil {
		scan = desync.Scan
	}
	e.desyncScan = &desync.ScanResult{Reason: "running"}
	e.publishOperationLocked("desync_scan")
	e.mu.Unlock()
	result := scan(ctx, desync.ScanConfig{
		Host: failedHost, VerifyHosts: hosts,
		Timeout: desync.ScanEnvTimeout(),
		SkipIDs: map[string]struct{}{cfg.Strategy.ID: {}},
		Start:   desync.StartFunc(start), Resolve: cfg.Resolve, AssignJob: cfg.AssignJob,
		BinaryPath: cfg.BinaryPath, ConnIP: cfg.ConnIP, BindInterface: cfg.BindInterface,
	})
	e.mu.Lock()
	defer func() {
		if generation == e.sessionGeneration {
			e.strategySwitching = false
			e.publishOperationLocked("")
		}
		e.mu.Unlock()
	}()
	if !e.currentSessionLocked(generation) || ctx.Err() != nil {
		return
	}
	e.desyncScan = &result
	if e.des != original || e.pathError == nil {
		result.OK, result.Reason = false, "superseded"
		return
	}
	slog.Info("engine: desync fallback scan", "result", desync.FormatScanSummary(result))
	if !result.OK || !desync.UsableOnOS(result.Strategy) || len(result.Strategy.Args) == 0 {
		if result.OK {
			result.OK, result.Reason = false, "invalid_strategy"
		}
		return
	}
	e.strategySwitching = true
	if err := e.des.Close(); err != nil {
		result.OK, result.Reason = false, "cleanup_failed"
		return
	}
	stopped := e.des.Info()
	e.desyncInfo = &stopped
	e.des = nil
	// Startup probes must not update the policy before all hosts pass.
	winner := cfg
	winner.Strategy = result.Strategy
	winner.ProbeHost = ""
	winner.ProbeTimeout = desync.ScanPerStrategyTimeout
	dataplane := e.tun
	e.publishOperationLocked("desync_verify")
	e.mu.Unlock()
	sess, err := start(winner)
	verified := false
	if err == nil && sess != nil && sess.Info().Up {
		verified = true
		for _, host := range hosts {
			if sess.ProbeTLS(host).Class != desync.FailOK || dataplane.ProbeTLS(host).Class != tunnel.FailOK {
				verified = false
				break
			}
		}
	}
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || ctx.Err() != nil {
		if sess != nil {
			_ = sess.Close()
		}
		return
	}
	if verified {
		e.des = sess
		e.desyncConfig = &winner
		info := sess.Info()
		e.desyncInfo = &info
		for _, host := range hosts {
			e.policy.OnDesyncOK(host, winner.Strategy.ID)
			applyProbeResult(e.targets, e.rulesetSnap.Doc, host, "ok", policy.PathDesync)
		}
		if e.strategyStore != nil {
			_ = e.strategyStore.Put(e.policy.ASN(), winner.Strategy, failedHost)
		}
		e.recordFailureLocked(diag.Failure{Component: "desync", Event: "strategy_recovered"})
		e.finishPathRecoveryLocked()
		return
	}
	if sess != nil {
		_ = sess.Close()
	}
	// A scan result alone is not connectivity. Roll back if the real helper
	// fails verification; retain degraded state and the original target paths.
	result.OK, result.Reason = false, "verification_failed"
	cfg.ProbeHost = ""
	e.mu.Unlock()
	restored, err := start(cfg)
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || ctx.Err() != nil {
		if restored != nil {
			_ = restored.Close()
		}
		return
	}
	e.des = restored
	if err != nil {
		slog.Warn("engine: restore desync strategy", "err", err)
	}
	if e.des != nil {
		info := e.des.Info()
		e.desyncInfo = &info
	}
}

func unavailablePathMessage(targets []ipc.TargetStatus) string {
	var labels []string
	for _, target := range targets {
		if target.Path == policy.PathTunnel && target.Outcome == "retry" {
			labels = append(labels, target.Label)
		}
	}
	message := "tunnel: protected path unavailable"
	if len(labels) > 0 {
		message += " (" + strings.Join(labels, ", ") + ")"
	}
	return message
}

const pathCheckInterval = 30 * time.Second

// Recheck the actual fallback SOCKS path, not just whether sing-box restarted.
// Network work runs outside mu and cannot publish into a later session.
func (e *Engine) recoverProtectedPath(generation uint64, now time.Time) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.strategySwitching || e.pathError == nil || e.rulesetSnap == nil ||
		e.des == nil || e.tun == nil || !e.des.Info().Up || !e.tun.Info().Up ||
		e.tun.ProviderID() != tunnel.ProviderDesync ||
		(!e.lastPathCheck.IsZero() && now.Sub(e.lastPathCheck) < pathCheckInterval) {
		e.mu.Unlock()
		return
	}
	e.lastPathCheck = now
	var hosts []string
	for _, host := range e.rulesetSnap.Doc.ProbeHosts() {
		if targetPath(e.targets, e.rulesetSnap.Doc.PackageIDForHost(host)) == policy.PathTunnel {
			hosts = append(hosts, host)
		}
	}
	sess, ctx := e.tun, e.sessionContextLocked()
	e.mu.Unlock()
	if len(hosts) == 0 {
		return
	}
	checks := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if ctx.Err() != nil || sess.ProbeTLS(host).Class != tunnel.FailOK {
			return
		}
		checks = append(checks, host)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.currentSessionLocked(generation) || ctx.Err() != nil || e.tun != sess || e.pathError == nil ||
		e.des == nil || !e.des.Info().Up {
		return
	}
	for _, host := range checks {
		e.policy.OnDesyncOK(host, e.des.StrategyID())
		applyProbeResult(e.targets, e.rulesetSnap.Doc, host, "ok", policy.PathDesync)
	}
	e.finishPathRecoveryLocked()
	e.publishOperationLocked("")
}

func (e *Engine) finishPathRecoveryLocked() {
	// Canary packages may still require a tunnel, independently of the two
	// visible targets. Do not clear their failure on unrelated TLS successes.
	want, _ := splitSpecialHosts(e.rulesetSnap.Doc, e.targets, e.policy)
	if len(want) > 0 {
		return
	}
	e.dataplaneTunnel = nil
	e.pathError = nil
	e.statusLocked()
	if component, _, _, _ := e.failedComponentLocked(); component == "" {
		e.state, e.summary = StateActive, "Açık"
		e.lastError = nil
	}
	e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "path_recovered"})
}
