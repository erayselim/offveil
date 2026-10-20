package engine

import (
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/policy"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

// Secondary checks cover distinct Discord connections without extending the
// synchronous startup/IPC budget or editing a signed ruleset. A host is used
// only when the enabled package already owns its routing suffix.
func secondaryProbeHosts(doc ruleset.Document) []string {
	var hosts []string
	for _, pkg := range doc.EnabledPackages() {
		if pkg.ID != "discord" || pkg.PathForce == "direct" {
			continue
		}
		for _, host := range []string{"updates.discord.com", "gateway.discord.gg", "stable.dl2.discordapp.net"} {
			if doc.PackageIDForHost(host) == pkg.ID {
				hosts = append(hosts, host)
			}
		}
	}
	return hosts
}

// Caller holds mu. The same endpoints must pass scanning, adoption and recovery;
// a working homepage must never clear an updater-specific failure.
func (e *Engine) verificationHostsLocked() []string {
	hosts := e.rulesetSnap.Doc.ProbeHosts()
	seen := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		seen[host] = true
	}
	for _, host := range e.extraProbeHosts {
		if !seen[host] {
			hosts = append(hosts, host)
			seen[host] = true
		}
	}
	return hosts
}

func (e *Engine) monitorProtectedEndpointsSession(generation uint64) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) {
		e.mu.Unlock()
		return
	}
	ctx := e.sessionContextLocked()
	e.mu.Unlock()
	for {
		e.checkProtectedEndpointsSession(generation)
		timer := time.NewTimer(time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (e *Engine) checkProtectedEndpointsSession(generation uint64) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.strategySwitching || e.pathError != nil ||
		e.tun == nil || e.des == nil || !e.tun.Info().Up || !e.des.Info().Up ||
		e.tun.ProviderID() != tunnel.ProviderDesync {
		e.mu.Unlock()
		return
	}
	hosts := append([]string(nil), e.extraProbeHosts...)
	dataplane, helper, ctx := e.tun, e.des, e.sessionContextLocked()
	e.mu.Unlock()
	for _, host := range hosts {
		if ctx.Err() != nil {
			return
		}
		sig := dataplane.ProbeTLS(host)
		if sig.Class == tunnel.FailOK {
			continue
		}
		// Confirm a transient failure before changing the accepted target policy.
		if ctx.Err() != nil {
			return
		}
		sig = dataplane.ProbeTLS(host)
		if sig.Class == tunnel.FailOK {
			continue
		}
		e.mu.Lock()
		if !e.currentSessionLocked(generation) || ctx.Err() != nil || e.strategySwitching ||
			e.tun != dataplane || e.des != helper || e.pathError != nil {
			e.mu.Unlock()
			return
		}
		e.policy.Put(host, policy.PathTunnel, string(sig.Class), "probe:protected_endpoint")
		applyProbeResult(e.targets, e.rulesetSnap.Doc, host, "retry", policy.PathTunnel)
		message := unavailablePathMessage(e.targets)
		e.pathError, e.lastError = &message, &message
		e.desyncScan = nil
		if e.strategyStore != nil {
			_ = e.strategyStore.Delete(e.policy.ASN())
		}
		e.state, e.summary = StateDegraded, "Bozuldu"
		e.lastPathCheck = time.Now()
		e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "endpoint_unavailable", Target: host, Reason: string(sig.Class)})
		e.publishOperationLocked("")
		e.mu.Unlock()
		e.recoverDesyncStrategySession(generation)
		e.promoteEndpointTunnelSession(generation, host)
		return
	}
}

// If a new endpoint failure survives strategy discovery, try the configured
// providers once without rebuilding DNS or the healthy ByeDPI helper. Failed
// promotion restores the local dataplane and keeps the original path error.
func (e *Engine) promoteEndpointTunnelSession(generation uint64, host string) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.pathError == nil || e.strategySwitching ||
		e.endpointTunnelTried || e.tunnelConfig == nil || e.tun == nil ||
		e.tun.ProviderID() != tunnel.ProviderDesync || !e.tun.Info().Up || e.rulesetSnap == nil {
		e.mu.Unlock()
		return
	}
	packageID := e.rulesetSnap.Doc.PackageIDForHost(host)
	// Discovery may have fixed this service while an independent target kept
	// the global path error. Do not promote a healthy service for that error.
	if packageID == "" || targetPath(e.targets, packageID) != policy.PathTunnel {
		e.mu.Unlock()
		return
	}
	previous, start, original := e.tun, e.startTunnel, *e.tunnelConfig
	if start == nil {
		e.mu.Unlock()
		return
	}
	cfg := original
	cfg.AllowlistOutbound, cfg.ProbeHost = "tunnel", host
	cfg.TunnelDomains, cfg.SpecialDomains = splitSpecialHosts(e.rulesetSnap.Doc, e.targets, e.policy)
	if len(cfg.TunnelDomains) == 0 {
		e.mu.Unlock()
		return
	}
	var verify []string
	for _, target := range e.verificationHostsLocked() {
		if e.rulesetSnap.Doc.PackageIDForHost(target) == packageID {
			verify = append(verify, target)
		}
	}
	ctx := e.sessionContextLocked()
	e.endpointTunnelTried, e.strategySwitching = true, true
	e.publishOperationLocked("endpoint_tunnel")
	if err := previous.Close(); err != nil {
		e.strategySwitching = false
		e.publishOperationLocked("")
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	next, err := start(cfg)
	verified := err == nil && next != nil && next.Info().Up && next.ProviderID() != tunnel.ProviderDesync
	if verified {
		for _, target := range verify {
			if ctx.Err() != nil || next.ProbeTLS(target).Class != tunnel.FailOK {
				verified = false
				break
			}
		}
	}
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || ctx.Err() != nil || e.tun != previous {
		e.mu.Unlock()
		if next != nil {
			_ = next.Close()
		}
		return
	}
	if verified {
		e.tun, e.tunnelConfig = next, &cfg
		info := next.Info()
		e.tunnelInfo = &info
		for _, target := range verify {
			e.policy.OnTunnelOK(target, string(next.ProviderID()))
			applyProbeResult(e.targets, e.rulesetSnap.Doc, target, "ok", policy.PathTunnel)
		}
		e.dataplaneTunnel = append([]string(nil), cfg.TunnelDomains...)
		covered := make(map[string]bool, len(cfg.TunnelDomains))
		for _, domain := range cfg.TunnelDomains {
			covered[domain] = true
		}
		allRecovered := true
		wanted, _ := splitSpecialHosts(e.rulesetSnap.Doc, e.targets, e.policy)
		for _, domain := range wanted {
			if !covered[domain] {
				allRecovered = false
			}
		}
		for _, target := range e.targets {
			if target.Path == policy.PathTunnel && target.Outcome == "retry" {
				allRecovered = false
			}
		}
		if allRecovered {
			e.pathError, e.lastError = nil, nil
			e.state, e.summary = StateActive, "Açık"
		}
		e.strategySwitching = false
		e.statusLocked() // Other failed components must still remain degraded.
		e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "endpoint_recovered", Target: host, Provider: string(next.ProviderID())})
		e.publishOperationLocked("")
		e.mu.Unlock()
		return
	}
	if next != nil {
		info := next.Info()
		info.FailDetail = ""
		e.tunnelFallback = &info
		for _, failure := range info.Failures {
			e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "provider_failed", Provider: string(failure.ProviderID), Reason: string(failure.Class) + ":" + failure.Reason, Exit: failure.Exit})
		}
		_ = next.Close()
	}
	e.mu.Unlock()
	restored, restoreErr := start(original)
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.currentSessionLocked(generation) || ctx.Err() != nil || e.tun != previous {
		if restored != nil {
			_ = restored.Close()
		}
		return
	}
	e.tun = restored
	if restored != nil {
		info := restored.Info()
		e.tunnelInfo = &info
	}
	e.strategySwitching = false
	e.lastError = e.pathError
	e.state, e.summary = StateDegraded, "Bozuldu"
	reason := "providers_unavailable"
	if restoreErr != nil || restored == nil || !restored.Info().Up {
		reason = "rollback_failed"
	}
	e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "endpoint_tunnel_failed", Target: host, Reason: reason})
	e.publishOperationLocked("")
}
