package engine

import (
	"context"
	"log/slog"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
	"github.com/erayselim/offveil/offveil-core/internal/netwatch"
	"github.com/erayselim/offveil/offveil-core/internal/power"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
)

const (
	healMinInterval = 8 * time.Second
	healSettleDelay = 1500 * time.Millisecond
)

// HealInfo is reliability diagnostics (status.heal; UI may ignore).
type HealInfo struct {
	LastReason string `json:"last_reason,omitempty"` // network_change | power_resume
	LastAt     string `json:"last_at,omitempty"`
	Count      int    `json:"count"`
	Watching   bool   `json:"watching"`
}

// startReliabilityLocked starts netwatch + power-resume self-heal (caller holds e.mu).
func (e *Engine) startReliabilityLocked() {
	e.stopReliabilityLocked()
	ctx, cancel := context.WithCancel(context.Background())
	e.reliabilityCancel = cancel
	e.healWatching = true

	netwatch.Start(ctx, netwatch.DefaultInterval, nil, func(prev, next string) {
		slog.Info("engine: network change detected", "from", prev, "to", next)
		e.requestHeal("network_change")
	})
	go power.Watch(ctx, func() {
		e.requestHeal("power_resume")
	})
}

func (e *Engine) stopReliabilityLocked() {
	if e.reliabilityCancel != nil {
		e.reliabilityCancel()
		e.reliabilityCancel = nil
	}
	e.healWatching = false
}

func (e *Engine) requestHeal(reason string) {
	go e.SelfHeal(reason)
}

// SelfHeal silently rebuilds the protection stack after network change or wake.
// Debounced; no-op when protection is off. Matches UI “Yenile” (stop+start)
// so TUN routes / sidecars rebind after Windows rebuilds the route table.
func (e *Engine) SelfHeal(reason string) {
	e.healMu.Lock()
	defer e.healMu.Unlock()

	if reason == "" {
		reason = "unknown"
	}

	e.mu.Lock()
	if !e.protection || e.state == StateStopped || e.state == StateStopping || e.state == StateStarting {
		e.mu.Unlock()
		return
	}
	if !e.lastHealAt.IsZero() && time.Since(e.lastHealAt) < healMinInterval {
		e.mu.Unlock()
		slog.Info("engine: self-heal skipped (debounce)", "reason", reason)
		return
	}
	e.mu.Unlock()

	// Settle after Wi-Fi association / DHCP.
	time.Sleep(healSettleDelay)

	e.mu.Lock()
	if !e.protection || e.state == StateStopped || e.state == StateStopping {
		e.mu.Unlock()
		return
	}
	netFn := e.lookupNet
	if netFn == nil {
		netFn = netinfo.Lookup
	}
	e.mu.Unlock()

	nctx, ncancel := context.WithTimeout(context.Background(), 5*time.Second)
	ni := netFn(nctx)
	ncancel()

	e.mu.Lock()
	invalidated := false
	if e.policy != nil {
		invalidated = e.policy.ObserveNetwork(ni)
	}
	need := reason == "power_resume" || invalidated
	if !need {
		e.mu.Unlock()
		slog.Info("engine: self-heal skipped (network identity unchanged)", "reason", reason)
		return
	}
	e.mu.Unlock()

	slog.Info("engine: self-heal begin", "reason", reason, "asn", ni.ASN, "fp", ni.Fingerprint)

	if _, err := e.Stop(); err != nil {
		slog.Warn("engine: self-heal stop", "err", err.Message)
	}
	time.Sleep(400 * time.Millisecond)
	st, err := e.Start("auto")
	e.mu.Lock()
	e.lastHealAt = time.Now().UTC()
	e.healCount++
	e.healReason = reason
	at := e.lastHealAt.Format(time.RFC3339)
	e.healAt = at
	e.mu.Unlock()

	if err != nil {
		slog.Warn("engine: self-heal start failed", "reason", reason, "err", err.Message)
		return
	}
	if st != nil {
		slog.Info("engine: self-heal done", "reason", reason, "state", st.State, "hint", st.OutboundHint)
	}
}

func (e *Engine) healInfoLocked() *HealInfo {
	if !e.healWatching && e.healCount == 0 {
		return nil
	}
	return &HealInfo{
		LastReason: e.healReason,
		LastAt:     e.healAt,
		Count:      e.healCount,
		Watching:   e.healWatching,
	}
}

// Diagnostics builds a PII-safe zip under ProgramData/offveil/diagnostics.
func (e *Engine) Diagnostics() (*diag.BundleMeta, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.protection {
		e.freezeSupportLocked()
	}
	if e.lastSupport != nil {
		in := *e.lastSupport
		in.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		if !e.protection {
			in.Notes = append(append([]string{}, in.Notes...),
				"Protection is currently off; cascade/sidecars are from the last active session.")
		}
		if e.policy != nil {
			if a := e.policy.ASN(); a != "" {
				in.Network.ASN = a
			}
			if h := e.policy.ISPHint(); h != "" {
				in.Network.ISPHint = h
			}
			if fp := e.policy.Fingerprint(); fp != "" {
				in.Network.Fingerprint = fp
			}
		}
		return diag.WriteZip(in)
	}
	return diag.WriteZip(e.buildDiagInputLocked())
}

func (e *Engine) freezeSupportLocked() {
	in := e.buildDiagInputLocked()
	e.lastSupport = &in
}

func (e *Engine) buildDiagInputLocked() diag.Input {
	st := e.statusLocked()
	// When stopped, prefer frozen sidecars/targets from lastSupport if building fresh
	// would be empty - freezeSupport always calls this while still active.
	in := diag.Input{
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Network: diag.NetworkInfo{
			ASN:         e.policy.ASN(),
			ISPHint:     e.policy.ISPHint(),
			Fingerprint: e.policy.Fingerprint(),
		},
		Cascade: diag.CascadeInfo{
			State:        st.State,
			Protection:   st.Protection,
			Summary:      st.Summary,
			OutboundHint: st.OutboundHint,
			Health:       st.Health,
		},
		Sidecars: map[string]any{},
	}
	for _, t := range st.Targets {
		in.Cascade.Targets = append(in.Cascade.Targets, diag.TargetRow{
			ID: t.ID, Label: t.Label, Outcome: t.Outcome, Path: t.Path,
		})
	}
	if st.LastError != nil {
		in.Cascade.LastError = *st.LastError
	}
	if e.lastProbe != nil {
		in.Probe = probeToDiag(e.lastProbe)
	}
	if st.Capture != nil {
		in.Sidecars["capture"] = scrubSidecar(st.Capture)
	}
	if st.DNS != nil {
		in.Sidecars["dns"] = scrubSidecar(st.DNS)
	}
	if st.Desync != nil {
		in.Sidecars["desync"] = scrubSidecar(st.Desync)
	}
	if st.Tunnel != nil {
		in.Sidecars["tunnel"] = scrubSidecar(st.Tunnel)
	}
	if st.UDP != nil {
		in.Sidecars["udp"] = st.UDP
	}
	if st.Expand != nil {
		in.Sidecars["expand"] = st.Expand
	}
	if st.Ruleset != nil {
		if m, ok := st.Ruleset.(map[string]any); ok {
			in.Ruleset = m
		}
	}
	if h := e.healInfoLocked(); h != nil {
		in.Heal = map[string]any{
			"last_reason": h.LastReason,
			"last_at":     h.LastAt,
			"count":       h.Count,
			"watching":    h.Watching,
		}
	}
	return in
}

func probeToDiag(rep *probe.Report) *diag.ProbeInfo {
	if rep == nil {
		return nil
	}
	out := &diag.ProbeInfo{ASN: rep.ASN, ISPHint: rep.ISPHint}
	for _, r := range rep.Results {
		out.Results = append(out.Results, diag.ProbeRow{
			Target: r.Target,
			Class:  string(r.Class),
			Path:   r.Path,
			OK:     r.OK,
		})
	}
	return out
}

func scrubSidecar(v any) any {
	return diag.ScrubTree(v)
}