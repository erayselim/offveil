package engine

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

const (
	groupFailureThreshold = 2
	groupRetryInterval    = 10 * time.Minute
	crisisEvery           = 5 // monitor rounds between crisis-group checks
	tunnelPrepareBudget   = 60 * time.Second
)

type groupState struct {
	ID, Label, Kind string
	Hosts           []string
	Suffixes        []string
	Path            string
	Class           string
	OK              bool
	Checked         bool
	Failures        int
	Unreachable     bool
	CheckedAt       string
	LastScan        time.Time
	LastEscalation  time.Time
}

// GroupHealth is the exported group view. IDs and labels come from the
// signed ruleset; no user destination is ever listed.
type GroupHealth struct {
	ID          string `json:"id"`
	Label       string `json:"label,omitempty"`
	Kind        string `json:"kind"`
	Path        string `json:"path"`
	Healthy     bool   `json:"healthy"`
	Checked     bool   `json:"checked"`
	Unreachable bool   `json:"unreachable,omitempty"`
	Class       string `json:"class,omitempty"`
	CheckedAt   string `json:"checked_at,omitempty"`
}

func (e *Engine) initGroupsLocked(doc ruleset.Document) {
	e.groups = nil
	for _, group := range doc.Canaries {
		e.groups = append(e.groups, &groupState{ID: group.ID, Label: group.Label, Kind: group.Kind,
			Hosts: append([]string(nil), group.ProbeHosts...), Suffixes: append([]string(nil), group.DomainSuffix...),
			Path: tunnel.PathDesync})
	}
}

func (e *Engine) groupRoutesLocked() []tunnel.GroupRoute {
	var out []tunnel.GroupRoute
	for _, g := range e.groups {
		out = append(out, tunnel.GroupRoute{ID: g.ID, DomainSuffix: append([]string(nil), g.Suffixes...)})
	}
	return out
}

func (e *Engine) groupPathsLocked() map[string]string {
	out := map[string]string{}
	for _, g := range e.groups {
		out[g.ID] = g.Path
	}
	return out
}

func (e *Engine) groupLocked(id string) *groupState {
	for _, g := range e.groups {
		if g.ID == id {
			return g
		}
	}
	return nil
}

func (e *Engine) canaryGroupsLocked() []ruleset.CanaryGroup {
	var out []ruleset.CanaryGroup
	for _, g := range e.groups {
		out = append(out, ruleset.CanaryGroup{ID: g.ID, Kind: g.Kind, ProbeHosts: g.Hosts, DomainSuffix: g.Suffixes})
	}
	return out
}

func (e *Engine) groupHealthLocked() []GroupHealth {
	var out []GroupHealth
	for _, g := range e.groups {
		path := g.Path
		if e.layer != layerSelective {
			path = "direct"
		}
		out = append(out, GroupHealth{ID: g.ID, Label: g.Label, Kind: g.Kind, Path: path, Healthy: g.OK,
			Checked: g.Checked, Unreachable: g.Unreachable, Class: g.Class, CheckedAt: g.CheckedAt})
	}
	return out
}

// probeGroups measures each due group's first host through the live gateway.
func probeGroups(session tunnel.Session, groups []*groupState) map[string]tunnel.FailSignal {
	out := make(map[string]tunnel.FailSignal, len(groups))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, g := range groups {
		host := g.Hosts[0]
		wg.Go(func() {
			sig := session.ProbeTLS(host)
			mu.Lock()
			out[g.ID] = sig
			mu.Unlock()
		})
	}
	wg.Wait()
	return out
}

// escalateGroupSession moves one group to the tunnel. If the gateway has no
// tunnel yet, the tunnel is prepared off the lifecycle lock and the gateway is
// rebuilt once; other traffic keeps working on desync meanwhile.
func (e *Engine) escalateGroupSession(generation uint64, id string) {
	e.mu.Lock()
	g := e.groupLocked(id)
	if !e.currentSessionLocked(generation) || g == nil || e.tun == nil || e.layer != layerSelective {
		e.groupWork = false
		e.mu.Unlock()
		return
	}
	g.LastEscalation = time.Now()
	session, ctx := e.tun, e.sessionContextLocked()
	selective, hasTunnel := session.(tunnel.SelectiveSession)
	hasTunnel = hasTunnel && selective.TunnelAvailable()
	var cfg tunnel.Config
	if e.tunnelConfig != nil {
		cfg = *e.tunnelConfig
	}
	scope := e.strategyScopeLocked()
	prepare := e.prepareTunnel
	if prepare == nil {
		prepare = defaultPrepareTunnel
	}
	e.mu.Unlock()

	if !hasTunnel {
		pctx, cancel := context.WithTimeout(ctx, tunnelPrepareBudget)
		provider, profile, trials, err := prepare(pctx, cfg, scope)
		cancel()
		e.mu.Lock()
		if !e.currentSessionLocked(generation) || e.tun != session {
			e.groupWork = false
			e.mu.Unlock()
			return
		}
		e.tunnelTrials = trials
		if err != nil || provider == "" {
			e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "tunnel_unavailable", Target: id, Reason: diag.Scrub(errText(err))})
			g.Unreachable, e.groupWork = true, false
			e.refreshNetworkStatusLocked()
			e.publishOperationLocked("")
			e.mu.Unlock()
			return
		}
		next := cfg
		next.TunnelProvider, next.WARPProfile = provider, profile
		next.GroupPaths = e.groupPathsLocked()
		next.GroupPaths[id] = tunnel.PathTunnel
		if !e.rebuildGatewayLocked(next) {
			g.Unreachable, e.groupWork = true, false
			e.refreshNetworkStatusLocked()
			e.publishOperationLocked("")
			e.mu.Unlock()
			return
		}
		g.Path = tunnel.PathTunnel
		session = e.tun
		e.mu.Unlock()
	} else if err := selective.SetGroupPath(ctx, id, tunnel.PathTunnel); err != nil {
		e.mu.Lock()
		e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "group_switch_failed", Target: id, Reason: diag.Scrub(err.Error())})
		g.Unreachable, e.groupWork = true, false
		e.refreshNetworkStatusLocked()
		e.mu.Unlock()
		return
	}
	sig := session.ProbeTLS(g.Hosts[0])
	e.mu.Lock()
	defer e.mu.Unlock()
	e.groupWork = false
	if !e.currentSessionLocked(generation) || e.tun != session {
		return
	}
	g.Path, g.Class, g.CheckedAt = tunnel.PathTunnel, string(sig.Class), time.Now().UTC().Format(time.RFC3339)
	if e.tunnelConfig != nil {
		e.tunnelConfig.GroupPaths = e.groupPathsLocked()
	}
	if sig.Class == tunnel.FailOK {
		g.OK, g.Failures, g.Unreachable = true, 0, false
		e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "group_tunneled", Target: id})
	} else {
		g.OK, g.Unreachable = false, true
		e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "group_unreachable", Target: id, Class: string(sig.Class)})
	}
	e.refreshNetworkStatusLocked()
	e.publishOperationLocked("")
}

// rebuildGatewayLocked replaces the gateway with next and restores the
// previous configuration if the new one cannot attach. Caller holds mu.
func (e *Engine) rebuildGatewayLocked(next tunnel.Config) bool {
	previous := e.tunnelConfig
	e.strategySwitching = true
	e.publishOperationLocked("transport_recovery")
	defer func() { e.strategySwitching = false }()
	if e.tun != nil {
		_ = e.tun.Close()
		e.tun = nil
	}
	start := func(cfg tunnel.Config) bool {
		e.cleanOrphanLocked()
		session, err := e.startTunnel(cfg)
		if err != nil || session == nil || !session.Info().Up {
			if session != nil {
				_ = session.Close()
			}
			e.recordStartupFailuresLocked(err)
			return false
		}
		if err := e.attachLocked(session); err != nil {
			_ = session.Close()
			return false
		}
		e.tun, e.tunnelConfig = session, &cfg
		info := session.Info()
		e.tunnelInfo = &info
		return true
	}
	if start(next) {
		e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "gateway_rebuilt", Provider: string(next.TunnelProvider)})
		return true
	}
	if previous != nil && start(*previous) {
		e.recordFailureLocked(diag.Failure{Component: "tunnel", Event: "gateway_restored"})
	}
	return false
}

func (e *Engine) cleanOrphanLocked() {
	if e.closeOrphan == nil {
		return
	}
	if err := e.closeOrphan(); err != nil {
		slog.Warn("engine: orphan adapter cleanup", "err", err)
	}
}

func (e *Engine) attachLocked(session tunnel.Session) error {
	started := time.Now()
	err := attachCaptureAdapter(e.sessionContextLocked(), e.cap, capture.AdapterName, session)
	e.attachTook = time.Since(started).Round(10 * time.Millisecond).String()
	if err != nil {
		class := "timeout"
		if session != nil && !session.Info().Up {
			class = "gateway_exit"
		}
		reason := ""
		if s, ok := session.(tunnel.SelectiveSession); ok {
			reason = s.StderrClass()
		}
		e.recordFailureLocked(diag.Failure{Component: "engine", Event: "adapter_attach_failed", Stage: "adapter_attach", Class: class, Reason: reason})
		return err
	}
	if e.cap != nil {
		info := e.cap.Info()
		e.captureInfo = &info
	}
	return nil
}

func defaultPrepareTunnel(ctx context.Context, cfg tunnel.Config, scope string) (tunnel.ProviderID, *tunnel.WARPProfile, []tunnel.EndpointTrial, error) {
	if reality, err := tunnel.LoadRealityCredentials(cfg.Reality, cfg.DataDir); err == nil && reality != nil && cfg.PreferReality {
		return tunnel.ProviderReality, nil, nil, nil
	}
	profile, err := tunnel.PrepareWARP(ctx, cfg)
	if err != nil {
		if reality, rerr := tunnel.LoadRealityCredentials(cfg.Reality, cfg.DataDir); rerr == nil && reality != nil {
			return tunnel.ProviderReality, nil, nil, nil
		}
		return "", nil, nil, err
	}
	pinned, trials, err := tunnel.PreflightWARP(ctx, cfg, profile, scope)
	if err != nil {
		if reality, rerr := tunnel.LoadRealityCredentials(cfg.Reality, cfg.DataDir); rerr == nil && reality != nil {
			return tunnel.ProviderReality, nil, trials, nil
		}
		return "", nil, trials, err
	}
	return tunnel.ProviderWARP, pinned, trials, nil
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
