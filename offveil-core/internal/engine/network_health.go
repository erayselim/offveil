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

const networkCheckInterval = 30 * time.Second
const transportRetryInterval = 2 * time.Minute

// NetworkHealth describes coverage separately from process liveness. No
// application endpoint can narrow or broaden the public network's route.
type NetworkHealth struct {
	Mode           string   `json:"mode"`
	Coverage       string   `json:"coverage"`
	TCPPath        string   `json:"tcp_path"`
	UDPPath        string   `json:"udp_path"`
	IPv4           bool     `json:"ipv4"`
	IPv6           bool     `json:"ipv6"`
	Healthy        bool     `json:"healthy"`
	CheckedAt      string   `json:"checked_at,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	BypassFamilies []string `json:"bypass_families"`
}

func networkTargets(path string, healthy bool) []ipc.TargetStatus {
	outcome := "unknown"
	if healthy {
		outcome = "ok"
	}
	tcp, udp := path, path
	if path == policy.PathDesync {
		outcome, udp = "limited", policy.PathDirect
	}
	return []ipc.TargetStatus{
		{ID: "tcp", Label: "TCP", Path: tcp, Outcome: outcome},
		{ID: "udp", Label: "UDP", Path: udp, Outcome: outcome},
	}
}

func (e *Engine) networkModeLocked() string {
	if e.tunnelInfo == nil {
		return "unavailable"
	}
	if e.tunnelInfo.Mode != "" {
		return e.tunnelInfo.Mode
	}
	if e.tunnelInfo.ProviderID == tunnel.ProviderDesync {
		return "local"
	}
	return "remote"
}

// Caller holds mu. A fallback helper is optional while remote transport works.
func (e *Engine) componentRequiredLocked(component string) bool {
	return component != "desync" || e.networkModeLocked() != "remote"
}

func (e *Engine) refreshNetworkStatusLocked() {
	if !e.protection {
		return
	}
	mode := e.networkModeLocked()
	network := &NetworkHealth{Mode: mode, IPv4: true, IPv6: true}
	if e.networkCheck != nil {
		network.CheckedAt = e.networkCheck.CheckedAt
	}
	if mode == "remote" {
		network.Coverage, network.TCPPath, network.UDPPath = "public_tcp_udp_dual_stack", policy.PathTunnel, policy.PathTunnel
		network.BypassFamilies = []string{"ipv4", "ipv6"}
	} else {
		network.Coverage, network.TCPPath, network.UDPPath = "tls_http_only", policy.PathDesync, policy.PathDirect
		network.Reason = "remote_transport_unavailable"
		network.BypassFamilies = []string{"ipv4"}
	}
	if e.tun != nil {
		info := e.tun.Info()
		e.tunnelInfo = &info
		network.Healthy = info.Up && (info.Healthy || info.Mode == "" && (info.LastProbe == tunnel.FailOK || info.LastProbe == ""))
		if e.networkCheck != nil && e.networkCheck.CheckedAt != "" {
			network.Healthy = info.Up && e.networkCheck.Healthy
		}
	}
	e.networkCheck = network
	e.targets = networkTargets(network.TCPPath, network.Healthy)
	component, failed, _, _ := e.failedComponentLocked()
	if component != "" && e.componentRequiredLocked(component) {
		network.Healthy = false
		for i := range e.targets {
			e.targets[i].Outcome = "failed"
		}
		e.state, e.summary, network.Reason = StateDegraded, "Bozuldu", "component_unavailable"
		e.lastError = &failed
		return
	}
	if e.networkFailures >= 2 {
		message := "network: independent connectivity controls failed"
		e.state, e.summary, e.lastError = StateDegraded, "Bozuldu", &message
		network.Reason = "control_quorum_failed"
	} else if mode == "remote" {
		e.state, e.summary, e.lastError = StateActive, "Açık", nil
	} else {
		e.state, e.summary, e.lastError = StateDegraded, "Sınırlı koruma", nil
	}
	e.targets = networkTargets(network.TCPPath, network.Healthy)
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

func probeControlQuorum(session tunnel.Session, hosts []string) bool {
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for _, host := range hosts {
		wg.Go(func() {
			if session.ProbeTLS(host).Class == tunnel.FailOK {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return len(hosts) >= 2 && passed >= 2
}

// All network work is outside the lifecycle lock and bound to its session.
func (e *Engine) checkNetworkSession(generation uint64, now time.Time) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.strategySwitching || e.tun == nil || !e.tun.Info().Up ||
		(!e.lastPathCheck.IsZero() && now.Sub(e.lastPathCheck) < networkCheckInterval) {
		e.mu.Unlock()
		return
	}
	session, hosts, ctx := e.tun, e.controlHostsLocked(), e.sessionContextLocked()
	e.lastPathCheck = now
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 16*time.Second)
	healthy := false
	if checker, ok := session.(interface{ CheckHealth(context.Context) bool }); ok {
		healthy = checker.CheckHealth(ctx)
	} else {
		healthy = probeControlQuorum(session, hosts)
	}
	cancel()
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.tun != session {
		e.mu.Unlock()
		return
	}
	if healthy {
		e.networkFailures = 0
	} else {
		e.networkFailures++
	}
	if e.networkCheck == nil {
		e.networkCheck = &NetworkHealth{}
	}
	e.networkCheck.CheckedAt = now.UTC().Format(time.RFC3339)
	e.networkCheck.Healthy = healthy
	e.refreshNetworkStatusLocked()
	retry := e.networkModeLocked() == "local" || e.networkFailures >= 2
	retry = retry && (e.lastTransportRetry.IsZero() || now.Sub(e.lastTransportRetry) >= transportRetryInterval)
	if retry {
		e.lastTransportRetry = now
	}
	localScan := e.networkModeLocked() == "local" && e.networkFailures >= 2 && e.desyncScan == nil
	e.publishOperationLocked("")
	e.mu.Unlock()
	if retry {
		e.refreshTransportSession(generation, session)
	}
	if localScan {
		e.recoverDesyncStrategySession(generation)
	}
}

func (e *Engine) refreshTransportSession(generation uint64, session tunnel.Session) {
	refresher, ok := session.(interface{ RefreshTransport(context.Context) error })
	if !ok {
		return
	}
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.tun != session || e.strategySwitching {
		e.mu.Unlock()
		return
	}
	ctx := e.sessionContextLocked()
	before := session.Info()
	e.strategySwitching = true
	e.publishOperationLocked("transport_recovery")
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 24*time.Second)
	err := refresher.RefreshTransport(ctx)
	cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.currentSessionLocked(generation) || e.tun != session {
		return
	}
	e.strategySwitching = false
	info := session.Info()
	e.tunnelInfo = &info
	// A failed remote attempt can still restore a verified local path. Its
	// controls must not inherit the failed remote path's debounce counter.
	if info.Up && info.Healthy {
		e.networkFailures = 0
	}
	e.networkCheck = &NetworkHealth{Healthy: info.Healthy, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	event := "transport_recovered"
	if err != nil {
		event = "transport_retry_failed"
	}
	if before.Mode != info.Mode && info.Up && info.Healthy {
		if info.Mode == "local" {
			event = "transport_demoted"
		} else {
			event = "transport_promoted"
		}
	}
	e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: event, Provider: string(info.ProviderID),
		Stage: "transport_refresh", FromMode: before.Mode, ToMode: info.Mode})
	e.refreshNetworkStatusLocked()
	e.publishOperationLocked("")
}
