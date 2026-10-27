package engine

import (
	"context"
	"sync"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/policy"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

const (
	networkCheckInterval   = 30 * time.Second
	transportRetryInterval = 2 * time.Minute
	reclassifyInterval     = 5 * time.Minute
	groupProbeBudget       = 16 * time.Second
)

// Network reasons the UI distinguishes. Only "broken" ones set state=degraded.
const (
	ReasonOffline        = "offline"
	ReasonDNSOnly        = "dns_only_fallback"
	ReasonGroup          = "group_unreachable"
	ReasonRecovering     = "recovering"
	ReasonComponent      = "component_unavailable"
	ReasonDNSUnavailable = "dns_unavailable"
)

// LayerStatus shows each protection layer separately.
type LayerStatus struct {
	DNS    string `json:"dns"`
	TCP    string `json:"tcp"`
	Tunnel string `json:"tunnel"`
}

// NetworkHealth describes the active layers, the measured filtering and the
// canary groups. Process liveness and endpoint diagnostics stay separate.
type NetworkHealth struct {
	Mode           string        `json:"mode"`
	Coverage       string        `json:"coverage"`
	DPI            string        `json:"dpi,omitempty"`
	Layers         LayerStatus   `json:"layers"`
	Groups         []GroupHealth `json:"groups,omitempty"`
	TCPPath        string        `json:"tcp_path"`
	UDPPath        string        `json:"udp_path"`
	IPv4           bool          `json:"ipv4"`
	IPv6           bool          `json:"ipv6"`
	Healthy        bool          `json:"healthy"`
	CheckedAt      string        `json:"checked_at,omitempty"`
	Reason         string        `json:"reason,omitempty"`
	BypassFamilies []string      `json:"bypass_families"`
}

func networkTargets(path string, healthy bool) []ipc.TargetStatus {
	outcome := "unknown"
	if healthy {
		outcome = "ok"
	}
	return []ipc.TargetStatus{
		{ID: "tcp", Label: "TCP", Path: path, Outcome: outcome},
		{ID: "udp", Label: "UDP", Path: policy.PathDirect, Outcome: outcome},
	}
}

func (e *Engine) networkModeLocked() string {
	if e.layer == "" {
		return "unavailable"
	}
	return e.layer
}

// Caller holds mu. The helper and gateway are required only in the TCP layer.
func (e *Engine) componentRequiredLocked(component string) bool {
	switch component {
	case "dns":
		return true
	case "desync", "tunnel":
		return e.layer == layerSelective
	}
	return false
}

func (e *Engine) recoveryExhaustedLocked(component string) bool {
	return e.recoveryAttempts[component] >= recoveryBudget
}

func (e *Engine) refreshNetworkStatusLocked() {
	if !e.protection {
		return
	}
	network := &NetworkHealth{Mode: e.networkModeLocked(), IPv4: true, Groups: e.groupHealthLocked(),
		Layers: LayerStatus{DNS: "up", TCP: "off", Tunnel: "off"}, UDPPath: policy.PathDirect, TCPPath: policy.PathDirect}
	if e.classification != nil {
		network.DPI, network.CheckedAt = e.classification.DPI, e.classification.CheckedAt
	}
	if e.dnsInfo != nil && !e.dnsInfo.StubUp {
		network.Layers.DNS = "down"
	}
	switch e.layer {
	case layerSelective:
		network.Coverage, network.TCPPath, network.Layers.TCP = "dns_web_desync", policy.PathDesync, "up"
		network.BypassFamilies = []string{"ipv4"}
		if e.tun != nil {
			info := e.tun.Info()
			e.tunnelInfo = &info
			if !info.Up {
				network.Layers.TCP = "down"
			}
			if info.TunnelAvailable {
				network.Layers.Tunnel = "ready"
				for _, path := range info.GroupPaths {
					if path == tunnel.PathTunnel {
						network.Layers.Tunnel, network.Coverage = "up", "dns_web_desync_tunnel"
					}
				}
			}
		} else {
			network.Layers.TCP = "down"
		}
	case layerFallback:
		network.Coverage, network.Layers.TCP = "dns", "failed"
	default:
		network.Coverage = "dns"
	}
	if e.lastPathCheck.After(time.Time{}) {
		network.CheckedAt = e.lastPathCheck.UTC().Format(time.RFC3339)
	}
	e.networkCheck = network
	component, failed, _, _ := e.failedComponentLocked()
	switch {
	case component == "dns":
		network.Reason = ReasonDNSUnavailable
		e.state, e.summary, e.lastError = StateDegraded, "Bozuldu", &failed
	case component != "" && e.componentRequiredLocked(component) && e.recoveryExhaustedLocked(component):
		network.Reason = ReasonComponent
		e.state, e.summary, e.lastError = StateDegraded, "Bozuldu", &failed
	case component != "" && e.componentRequiredLocked(component):
		network.Reason = ReasonRecovering
		e.state, e.summary, e.lastError = StateActive, "Yeniden bağlanıyor", nil
	case e.classification != nil && e.classification.DPI == DPIOffline:
		network.Reason = ReasonOffline
		e.state, e.summary, e.lastError = StateActive, "Bağlantı yok", nil
	case e.layer == layerFallback:
		network.Reason = ReasonDNSOnly
		e.state, e.summary, e.lastError = StateActive, "Sınırlı koruma", nil
	case e.persistentUnreachableLocked():
		network.Reason = ReasonGroup
		e.state, e.summary, e.lastError = StateActive, "Sınırlı koruma", nil
	default:
		e.state, e.summary, e.lastError = StateActive, "Açık", nil
	}
	network.Healthy = network.Reason == ""
	e.targets = networkTargets(network.TCPPath, network.Healthy)
	if network.Reason == ReasonComponent || network.Reason == ReasonDNSUnavailable {
		for i := range e.targets {
			e.targets[i].Outcome = "failed"
		}
	}
}

func (e *Engine) persistentUnreachableLocked() bool {
	for _, g := range e.groups {
		if g.Kind == ruleset.CanaryPersistent && g.Unreachable {
			return true
		}
	}
	return false
}

func (e *Engine) controlHostsLocked() []string {
	if len(e.extraProbeHosts) > 0 {
		return append([]string(nil), e.extraProbeHosts...)
	}
	if e.rulesetSnap != nil {
		return e.rulesetSnap.Doc.ProbeHosts()
	}
	return ruleset.DefaultControlHosts()
}

func (e *Engine) monitorNetworkSession(generation uint64) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) {
		e.mu.Unlock()
		return
	}
	ctx := e.sessionContextLocked()
	e.mu.Unlock()
	for {
		e.checkNetworkSession(generation, time.Now())
		timer := time.NewTimer(networkCheckInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func quorum(results map[string]tunnel.FailSignal, hosts []string) bool {
	passed := 0
	for _, host := range hosts {
		if results[host].Class == tunnel.FailOK {
			passed++
		}
	}
	return len(hosts) >= 2 && passed >= 2
}

func probeHosts(probe func(string) tunnel.FailSignal, hosts []string) map[string]tunnel.FailSignal {
	out := make(map[string]tunnel.FailSignal, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, host := range hosts {
		wg.Go(func() {
			sig := probe(host)
			mu.Lock()
			out[host] = sig
			mu.Unlock()
		})
	}
	wg.Wait()
	return out
}

// checkNetworkSession runs one monitor round outside the lifecycle lock.
func (e *Engine) checkNetworkSession(generation uint64, now time.Time) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.strategySwitching || e.groupWork ||
		(!e.lastPathCheck.IsZero() && now.Sub(e.lastPathCheck) < networkCheckInterval) {
		e.mu.Unlock()
		return
	}
	e.lastPathCheck = now
	e.monitorRound++
	switch e.layer {
	case layerDNS, layerFallback:
		e.checkDNSLayerLocked(generation, now)
	case layerSelective:
		e.checkSelectiveLocked(generation, now)
	default:
		e.mu.Unlock()
	}
}

// checkDNSLayerLocked re-measures the network and turns on the TCP layer
// when filtering appears. Caller holds mu; the function releases it.
func (e *Engine) checkDNSLayerLocked(generation uint64, now time.Time) {
	retry := e.layer == layerFallback && e.layerRetries < layerRetryBudget && now.Sub(e.lastLayerTry) >= layerRetryInterval
	due := e.reclassify || e.lastClassify.IsZero() || now.Sub(e.lastClassify) >= reclassifyInterval
	if !retry && !due {
		e.mu.Unlock()
		return
	}
	ctx, probe, controls, groups := e.sessionContextLocked(), e.directProbe, e.controlHostsLocked(), e.canaryGroupsLocked()
	classify := e.classify
	if classify == nil {
		classify = classifyNetwork
	}
	e.mu.Unlock()
	var result *Classification
	if due && probe != nil {
		value := classify(ctx, probe, controls, groups)
		result = &value
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.currentSessionLocked(generation) || e.layer == layerSelective {
		return
	}
	if result != nil {
		e.applyClassificationLocked(*result)
	}
	escalate := e.layer == layerDNS && e.classification != nil && e.classification.DPI == DPIPresent
	if escalate || retry {
		if retry {
			e.layerRetries++
		}
		e.strategySwitching = true
		e.publishOperationLocked("transport_recovery")
		err := e.startLayer1Locked(nil)
		e.strategySwitching = false
		if err != nil {
			e.fallbackLocked(err)
		} else {
			e.recordFailureLocked(diag.Failure{Component: "engine", Event: "layer_started", Reason: e.classification.DPI})
		}
	}
	e.refreshNetworkStatusLocked()
	e.publishOperationLocked("")
}

// checkSelectiveLocked probes groups and controls through the gateway, then
// starts at most one repair: strategy scan, tunnel escalation or revert.
// Caller holds mu; the function releases it.
func (e *Engine) checkSelectiveLocked(generation uint64, now time.Time) {
	session := e.tun
	if session == nil || !session.Info().Up {
		e.mu.Unlock()
		return
	}
	var due []*groupState
	for _, g := range e.groups {
		if len(g.Hosts) == 0 {
			continue
		}
		if g.Kind == ruleset.CanaryPersistent || e.monitorRound%crisisEvery == 1 || g.Failures > 0 {
			if g.Unreachable && now.Sub(g.LastEscalation) < groupRetryInterval {
				continue
			}
			due = append(due, g)
		}
	}
	controls, ctx, probe := e.controlHostsLocked(), e.sessionContextLocked(), e.directProbe
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, groupProbeBudget)
	defer cancel()
	groupResults := probeGroups(session, due)
	gatewayControls := probeHosts(session.ProbeTLS, controls)
	offline := false
	if !quorum(gatewayControls, controls) && probe != nil {
		direct := probeHosts(func(host string) tunnel.FailSignal { return probe(ctx, host) }, controls)
		offline = !quorum(direct, controls)
	}

	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.tun != session || e.strategySwitching {
		e.mu.Unlock()
		return
	}
	if offline {
		e.classification = &Classification{DPI: DPIOffline, CheckedAt: now.UTC().Format(time.RFC3339)}
	} else if e.classification != nil && e.classification.DPI == DPIOffline {
		e.classification.DPI, e.reclassify = DPIPresent, true
	}
	stamp := now.UTC().Format(time.RFC3339)
	var action func()
	for _, g := range due {
		sig, ok := groupResults[g.ID]
		if !ok {
			continue
		}
		g.Checked, g.Class, g.CheckedAt = true, string(sig.Class), stamp
		if sig.Class == tunnel.FailOK {
			if g.Failures > 0 || g.Unreachable {
				e.recordFailureLocked(diag.Failure{Component: "network", Event: "group_recovered", Target: g.ID})
			}
			g.OK, g.Failures, g.Unreachable = true, 0, false
			continue
		}
		g.OK = false
		if offline {
			continue
		}
		g.Failures++
		if g.Failures < groupFailureThreshold || action != nil {
			continue
		}
		id := g.ID
		switch {
		case g.Path == tunnel.PathDesync && now.Sub(g.LastScan) >= groupRetryInterval && e.desyncScan == nil:
			g.LastScan = now
			action = func() { e.recoverDesyncStrategySession(generation, id) }
		case g.Path == tunnel.PathDesync:
			action = func() { e.escalateGroupSession(generation, id) }
		case g.Path == tunnel.PathTunnel:
			action = func() { e.revertGroupSession(generation, id) }
		}
	}
	if action != nil {
		e.groupWork = true
	}
	e.refreshNetworkStatusLocked()
	e.publishOperationLocked("")
	e.mu.Unlock()
	if action != nil {
		action()
	}
}

// revertGroupSession tries desync again for a group whose tunnel failed.
func (e *Engine) revertGroupSession(generation uint64, id string) {
	e.mu.Lock()
	g := e.groupLocked(id)
	session, ctx := e.tun, e.sessionContextLocked()
	selective, ok := session.(tunnel.SelectiveSession)
	if !e.currentSessionLocked(generation) || g == nil || !ok {
		e.groupWork = false
		e.mu.Unlock()
		return
	}
	g.LastEscalation = time.Now()
	e.mu.Unlock()
	err := selective.SetGroupPath(ctx, id, tunnel.PathDesync)
	sig := tunnel.FailSignal{Class: tunnel.FailConfig}
	if err == nil {
		sig = session.ProbeTLS(g.Hosts[0])
	}
	if err == nil && sig.Class != tunnel.FailOK {
		_ = selective.SetGroupPath(ctx, id, tunnel.PathTunnel)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.groupWork = false
	if !e.currentSessionLocked(generation) || e.tun != session {
		return
	}
	if err == nil && sig.Class == tunnel.FailOK {
		g.Path, g.OK, g.Failures, g.Unreachable = tunnel.PathDesync, true, 0, false
		e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "group_desync_restored", Target: id})
	} else {
		g.Unreachable = true
		e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "group_unreachable", Target: id, Class: string(sig.Class)})
	}
	if e.tunnelConfig != nil {
		e.tunnelConfig.GroupPaths = e.groupPathsLocked()
	}
	e.refreshNetworkStatusLocked()
	e.publishOperationLocked("")
}
