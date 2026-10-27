package engine

import (
	"context"
	"log/slog"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
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
	ctx, cancel := context.WithCancel(e.sessionContextLocked())
	e.reliabilityCancel = cancel
	e.healWatching = true
	session := e.sessionGeneration

	netwatch.Start(ctx, netwatch.DefaultInterval, nil, func(prev, next string) {
		slog.Info("engine: network change detected", "from", prev, "to", next)
		e.requestSessionHeal("network_change", session)
	})
	go power.Watch(ctx, func() {
		e.requestSessionHeal("power_resume", session)
	})
	go e.watchComponents(ctx, session)
}

func (e *Engine) stopReliabilityLocked() {
	if e.reliabilityCancel != nil {
		e.reliabilityCancel()
		e.reliabilityCancel = nil
	}
	e.healWatching = false
}

func (e *Engine) requestSessionHeal(reason string, session uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.currentSessionLocked(session) {
		e.requestHealLocked(reason)
	}
}

func (e *Engine) requestHealLocked(reason string) {
	go e.selfHeal(reason, e.lifecycleGeneration, e.sessionGeneration)
}

// SelfHeal silently rebuilds the protection stack after network change or wake.
// Debounced; no-op when protection is off. Matches UI “Yenile” (stop+start)
// so TUN routes / sidecars rebind after Windows rebuilds the route table.
func (e *Engine) SelfHeal(reason string) {
	e.mu.Lock()
	generation := e.lifecycleGeneration
	session := e.sessionGeneration
	e.mu.Unlock()
	e.selfHeal(reason, generation, session)
}

func (e *Engine) selfHeal(reason string, generation, session uint64) {
	e.healMu.Lock()
	defer e.healMu.Unlock()

	if reason == "" {
		reason = "unknown"
	}

	e.mu.Lock()
	if generation != e.lifecycleGeneration || !e.currentSessionLocked(session) {
		e.mu.Unlock()
		return
	}
	if reason == "network_change" || reason == "power_resume" {
		e.resetDNSCacheLocked()
	}
	delay := healSettleDelay
	if !e.lastHealAt.IsZero() {
		// A second real network change must wait for the cooldown instead of
		// being lost after policy already adopted that network identity.
		if remaining := healMinInterval - time.Since(e.lastHealAt); remaining > delay {
			delay = remaining
		}
	}
	ctx := e.sessionContextLocked()
	e.mu.Unlock()

	// Settle after Wi-Fi association / DHCP.
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	e.mu.Lock()
	if generation != e.lifecycleGeneration || !e.currentSessionLocked(session) {
		e.mu.Unlock()
		return
	}
	netFn := e.lookupNet
	if netFn == nil {
		netFn = netinfo.Lookup
	}
	e.mu.Unlock()

	nctx, ncancel := context.WithTimeout(ctx, 5*time.Second)
	ni := netFn(nctx)
	ncancel()

	e.mu.Lock()
	if generation != e.lifecycleGeneration || !e.currentSessionLocked(session) {
		e.mu.Unlock()
		return
	}
	if e.policy != nil {
		e.policy.ObserveNetwork(ni)
	}
	// Revalidate after settling: a reverted change or a relay ASN update must
	// not tear down a working physical binding.
	need := reason == "power_resume" || e.physicalNetworkChangedLocked(ni.Fingerprint)
	if !need {
		e.mu.Unlock()
		slog.Info("engine: self-heal skipped (network identity unchanged)", "reason", reason)
		return
	}
	slog.Info("engine: self-heal begin", "reason", reason, "asn", ni.ASN, "fp", ni.Fingerprint)
	if e.softRebindLocked(reason, ni.Fingerprint) {
		e.mu.Unlock()
		go e.checkNetworkSession(session, time.Now())
		return
	}
	e.recordFailureLocked(diag.Failure{Component: "engine", Event: "network_rebind", Reason: reason,
		FingerprintBefore: e.networkFingerprint, FingerprintAfter: ni.Fingerprint})
	e.healing = true

	if _, err := e.stopLocked(); err != nil {
		e.healing = false
		e.mu.Unlock()
		slog.Warn("engine: self-heal stop", "err", err.Message)
		return
	}
	stoppedSession := e.sessionGeneration
	e.mu.Unlock()
	time.Sleep(400 * time.Millisecond)
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		e.healing = false
		e.publishOperationLocked("")
	}()
	if generation != e.lifecycleGeneration || stoppedSession != e.sessionGeneration || e.state != StateStopped {
		return
	}
	st, err := e.startLocked("auto")
	e.lastHealAt = time.Now().UTC()
	e.healCount++
	e.healReason = reason
	at := e.lastHealAt.Format(time.RFC3339)
	e.healAt = at

	if err != nil {
		slog.Warn("engine: self-heal start failed", "reason", reason, "err", err.Message)
		return
	}
	if st != nil {
		slog.Info("engine: self-heal done", "reason", reason, "state", st.State, "hint", st.OutboundHint)
	}
}

// softRebindLocked keeps the TUN across a network change when the physical
// interface is the same: only the helper's source address and the
// measurements are refreshed. It reports false when a full rebuild is needed.
func (e *Engine) softRebindLocked(reason, fingerprint string) bool {
	rebind := func(mode string) {
		e.recordFailureLocked(diag.Failure{Component: "engine", Event: "network_rebind", Reason: reason, Stage: mode,
			FingerprintBefore: e.networkFingerprint, FingerprintAfter: fingerprint})
		e.networkFingerprint = fingerprint
		e.reclassify, e.lastPathCheck = true, time.Time{}
		for _, g := range e.groups {
			g.Failures, g.Unreachable = 0, false
		}
		e.lastHealAt = time.Now().UTC()
		e.healCount++
		e.healReason, e.healAt = reason, e.lastHealAt.Format(time.RFC3339)
		e.refreshNetworkStatusLocked()
		e.publishOperationLocked("")
	}
	if e.layer != layerSelective {
		rebind("measure")
		return true
	}
	if e.takeSnapshot == nil || e.captureInfo == nil || e.captureInfo.Egress == nil || e.desyncConfig == nil || e.des == nil {
		return false
	}
	snap, err := e.takeSnapshot()
	if err != nil || snap == nil || snap.Egress == nil || snap.Egress.Name != e.captureInfo.Egress.Name {
		return false
	}
	egress := *snap.Egress
	if egress.IPv4 != e.captureInfo.Egress.IPv4 {
		next := *e.desyncConfig
		next.ConnIP = egress.IPv4
		_ = e.des.Close()
		des, err := e.startDesync(next)
		if err != nil || des == nil {
			e.des, e.desyncConfig = nil, &next
			e.recordFailureLocked(diag.Failure{Component: "desync", Event: "rebind_failed"})
		} else {
			info := des.Info()
			e.des, e.desyncConfig, e.desyncInfo = des, &next, &info
		}
	}
	captureInfo := *e.captureInfo
	captureInfo.Egress = &egress
	e.captureInfo = &captureInfo
	rebind("soft")
	return true
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

func (e *Engine) resetDNSCacheLocked() {
	if e.doh != nil {
		e.doh.ResetCache()
	}
	if e.dns != nil {
		if client := e.dns.Client(); client != nil && client != e.doh {
			client.ResetCache()
		}
	}
}

// Diagnostics builds a PII-safe zip under ProgramData/offveil/diagnostics.
func (e *Engine) Diagnostics() (*diag.BundleMeta, error) {
	if !e.mu.TryLock() {
		if snapshot := e.operation.Load(); snapshot != nil {
			return snapshot.writeDiagnostics()
		}
		e.mu.Lock()
	}
	in := e.diagnosticsInputLocked()
	e.mu.Unlock()
	return writeDiagnostics(in)
}

func (e *Engine) diagnosticsInputLocked() diag.Input {
	if e.protection {
		e.freezeSupportLocked()
	}
	if e.lastSupport != nil {
		in := *e.lastSupport
		in.System = map[string]any{"protection_state": protectionState(e.protection)}
		in.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		if !e.protection && in.Cascade.Protection {
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
		return in
	}
	return e.buildDiagInputLocked()
}

func writeDiagnostics(in diag.Input) (*diag.BundleMeta, error) {
	// OS inspection and ZIP I/O must not hold the engine lifecycle lock.
	in.Failures = diag.ReadFailures()
	in.Notes = append(in.Notes, offdns.RelayDiagNotes()...)
	return diag.WriteZip(in)
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
		System:   map[string]any{"protection_state": protectionState(e.protection)},
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
	if e.tunnelFallback != nil {
		in.Sidecars["tunnel_fallback"] = scrubSidecar(e.tunnelFallback)
	}
	if e.desyncScan != nil {
		in.Sidecars["desync_scan"] = scrubSidecar(e.desyncScan)
	}
	if st.UDP != nil {
		in.Sidecars["udp"] = st.UDP
	}
	if st.Network != nil {
		in.Sidecars["network"] = st.Network
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

func protectionState(on bool) string {
	if on {
		return "on"
	}
	return "off"
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
