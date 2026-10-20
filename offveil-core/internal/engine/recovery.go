package engine

import (
	"context"
	"log/slog"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/proc"
)

const (
	componentInterval = 2 * time.Second
	recoveryCooldown  = 5 * time.Second
	recoveryBudget    = 2
)

func (e *Engine) failedComponentLocked() (component, reason string, pid int, exit *proc.ExitInfo) {
	switch {
	case e.dnsInfo != nil && !e.dnsInfo.StubUp:
		return "dns", "dns: local resolver stopped", 0, nil
	case !e.strategySwitching && e.desyncInfo != nil && !e.desyncInfo.Up:
		return "desync", "desync: sidecar exited", e.desyncInfo.PID, e.desyncInfo.Exit
	case !e.strategySwitching && e.des == nil && e.desyncConfig != nil:
		return "desync", "desync: sidecar unavailable", 0, nil
	case e.tunnelInfo != nil && !e.tunnelInfo.Up:
		return "tunnel", "tunnel: sidecar exited", e.tunnelInfo.PID, e.tunnelInfo.Exit
	case e.tun == nil && e.tunnelConfig != nil:
		return "tunnel", "tunnel: dataplane unavailable", 0, nil
	}
	return "", "", 0, nil
}

func (e *Engine) recordFailureLocked(failure diag.Failure) {
	failure.Generation = e.sessionGeneration
	if err := diag.RecordFailure(failure); err != nil {
		slog.Warn("engine: save failure", "err", err)
	}
}

func (e *Engine) watchComponents(ctx context.Context, generation uint64) {
	ticker := time.NewTicker(componentInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			e.recoverComponent(generation, now)
			e.recoverProtectedPath(generation, now)
		}
	}
}

func (e *Engine) recoverComponent(generation uint64, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.currentSessionLocked(generation) || e.strategySwitching {
		return
	}
	e.statusLocked()
	component, _, _, _ := e.failedComponentLocked()
	if component == "" {
		return
	}
	if e.recoveryAttempts == nil {
		e.recoveryAttempts = make(map[string]int)
	}
	attempt := e.recoveryAttempts[component]
	if attempt >= recoveryBudget {
		if attempt == recoveryBudget {
			e.recordFailureLocked(diag.Failure{Component: component, Event: "recovery_exhausted", Attempt: attempt})
			e.recoveryAttempts[component]++
		}
		return
	}
	if !e.lastRecovery.IsZero() && now.Sub(e.lastRecovery) < recoveryCooldown {
		return
	}
	e.recoveryAttempts[component]++
	e.lastRecovery = now
	e.publishOperationLocked("recovery_" + component)
	defer e.publishOperationLocked("")
	var err error
	event := "restart_failed"
	switch component {
	case "desync":
		if e.desyncConfig == nil || e.startDesync == nil {
			return
		}
		if e.des != nil {
			if err = e.des.Close(); err != nil {
				event = "cleanup_failed"
				break
			}
		}
		cfg := *e.desyncConfig
		cfg.ProbeHost = "" // Preserve the accepted session's routing policy during process recovery.
		e.des, err = e.startDesync(cfg)
	case "tunnel":
		if e.tunnelConfig == nil || e.startTunnel == nil {
			return
		}
		if e.tun != nil {
			if err = e.tun.Close(); err != nil {
				event = "cleanup_failed"
				break
			}
		}
		e.tun, err = e.startTunnel(*e.tunnelConfig)
	case "dns":
		if e.dnsConfig == nil || e.startDNS == nil {
			return
		}
		if e.dns != nil {
			if err = e.dns.Close(); err != nil {
				event = "cleanup_failed"
				break
			}
		}
		e.dns, err = e.startDNS(*e.dnsConfig)
	}
	// A failed start must not leave the previous process snapshot marked up.
	if err == nil {
		e.statusLocked()
		failed, _, _, _ := e.failedComponentLocked()
		restored := component == "desync" && e.des != nil && e.desyncInfo.Up ||
			component == "tunnel" && e.tun != nil && e.tunnelInfo.Up ||
			component == "dns" && e.dns != nil && e.dnsInfo.StubUp
		if restored {
			if failed == "" {
				e.failureKey = ""
				if e.pathError != nil {
					e.state, e.summary = StateDegraded, "Bozuldu"
					e.lastError = e.pathError
				} else {
					e.state, e.summary = StateActive, "Açık"
					e.lastError = nil
				}
			}
			e.recordFailureLocked(diag.Failure{Component: component, Event: "recovered", Attempt: attempt + 1})
			if e.pathError != nil && e.desyncScan == nil {
				// Initial local dataplane startup may have failed before a scan
				// could begin. Retry scheduling after component recovery.
				go e.recoverDesyncStrategySession(generation)
			}
			return
		}
	}
	if event == "cleanup_failed" {
		e.recoveryAttempts[component] = recoveryBudget
	}
	e.recordFailureLocked(diag.Failure{Component: component, Event: event, Attempt: attempt + 1})
	slog.Warn("engine: component recovery failed", "component", component, "attempt", attempt+1, "err", err)
}
