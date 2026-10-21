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
	case !e.strategySwitching && e.tunnelInfo != nil && !e.tunnelInfo.Up:
		return "tunnel", "tunnel: sidecar exited", e.tunnelInfo.PID, e.tunnelInfo.Exit
	case !e.strategySwitching && e.tun == nil && e.tunnelConfig != nil:
		return "tunnel", "tunnel: dataplane unavailable", 0, nil
	case !e.strategySwitching && e.desyncInfo != nil && !e.desyncInfo.Up:
		return "desync", "desync: sidecar exited", e.desyncInfo.PID, e.desyncInfo.Exit
	case !e.strategySwitching && e.des == nil && e.desyncConfig != nil:
		return "desync", "desync: sidecar unavailable", 0, nil
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
		}
	}
}
