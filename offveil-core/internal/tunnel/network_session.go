package tunnel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const networkStartupBudget = 16 * time.Second

type networkLauncher func(Config, providerAttempt) (*session, bool, FailClass, error)

// networkSession owns exactly one gateway/TUN. Provider candidates run behind
// private SOCKS listeners, so a failed provider trial never creates an adapter.
type networkSession struct {
	mu              sync.Mutex
	refreshMu       sync.Mutex
	cfg             Config
	cancel          context.CancelFunc
	launch          networkLauncher
	gateway, leaf   *session
	controls        []ControlResult
	gatewayControls []ControlResult
	healthy         bool
	failures        []ProviderFailure
	tried           []ProviderID
	closed          bool
	epoch           uint64
}

func startNetwork(cfg Config) (Session, error) { return startNetworkWith(cfg, startOne) }

func startNetworkWith(cfg Config, launch networkLauncher) (Session, error) {
	if err := normalizeControls(&cfg); err != nil {
		return nil, &StartupError{Err: err, Failures: []ProviderFailure{{Stage: "configuration", Class: FailConfig}}}
	}
	if cfg.ProviderListenPort == 0 {
		cfg.ProviderListenPort = 18082
	}
	if cfg.ProviderListenPort == cfg.ListenPort {
		return nil, &StartupError{Err: fmt.Errorf("gateway and provider listeners must differ"),
			Failures: []ProviderFailure{{Stage: "configuration", Class: FailConfig}}}
	}
	if cfg.ProbeTimeout <= 0 || cfg.ProbeTimeout > 5*time.Second {
		cfg.ProbeTimeout = 5 * time.Second
	}
	parent := cfg.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	cfg.Context = ctx
	n := &networkSession{cfg: cfg, cancel: cancel, launch: launch}
	startup, done := context.WithTimeout(ctx, networkStartupBudget)
	defer done()
	if cfg.AllowlistOutbound != "desync" {
		n.leaf, n.tried, n.failures = n.selectProvider(startup)
	}
	// Provider trials may consume their budget. A local gateway still needs its
	// own bounded readiness window, owned by the original protection session.
	readiness, finish := context.WithTimeout(ctx, 8*time.Second)
	defer finish()
	gateway, err := n.openGateway(readiness, n.leaf)
	if err != nil && n.leaf != nil && ctx.Err() == nil {
		_ = n.leaf.Close()
		n.leaf = nil
		// Remote routing can fail independently of local routing. Give the
		// fallback its own budget rather than aborting before it is attempted.
		fallback, stop := context.WithTimeout(ctx, 8*time.Second)
		defer stop()
		gateway, err = n.openGateway(fallback, nil)
		readiness = fallback
	}
	if err != nil {
		if n.leaf != nil {
			_ = n.leaf.Close()
		}
		cancel()
		return nil, &StartupError{Failures: append([]ProviderFailure(nil), n.failures...), Err: err}
	}
	n.gateway = gateway
	if cfg.SkipStart {
		if n.leaf != nil {
			n.controls, n.healthy = append([]ControlResult(nil), n.leaf.controls...), n.leaf.controlHealthy
		}
	} else {
		if !n.CheckHealth(readiness) && n.leaf != nil {
			// Leaf transport can work while gateway setup or its routing fails.
			// Keep the limited fallback explicit rather than claiming full coverage.
			n.recordControlFailure()
			_ = n.gateway.Close()
			_ = n.leaf.Close()
			n.leaf = nil
			fallback, stop := context.WithTimeout(ctx, 8*time.Second)
			defer stop()
			n.gateway, err = n.openGateway(fallback, nil)
			if err != nil {
				cancel()
				return nil, &StartupError{Failures: append([]ProviderFailure(nil), n.failures...), Err: err}
			}
			n.CheckHealth(fallback)
		}
	}
	return n, nil
}

func networkProviderOrder(cfg Config) []providerAttempt {
	reality, err := LoadRealityCredentials(cfg.Reality, cfg.DataDir)
	order := []providerAttempt{{ID: ProviderWARP}}
	if err == nil && reality != nil {
		order = append(order, providerAttempt{ID: ProviderReality, Reality: reality})
	}
	if cfg.PreferReality && len(order) > 1 {
		order[0], order[1] = order[1], order[0]
	}
	if !failoverEnabled(cfg) {
		order = order[:1]
	}
	return order
}

func (n *networkSession) selectProvider(ctx context.Context) (*session, []ProviderID, []ProviderFailure) {
	order := networkProviderOrder(n.cfg)
	var tried []ProviderID
	var failures []ProviderFailure
	for i, attempt := range order {
		if ctx.Err() != nil {
			break
		}
		budget := 8 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			budget = time.Until(deadline) / time.Duration(len(order)-i)
		}
		if budget <= 0 {
			break
		}
		attemptCtx, cancel := context.WithTimeout(ctx, budget)
		cfg := n.cfg
		cfg.EnableTUN = false
		cfg.providerOnly = true
		cfg.NetworkRoutes = nil
		cfg.upstreamSOCKS = ""
		cfg.ListenPort = cfg.ProviderListenPort
		cfg.ProbeHost = ""
		cfg.startupContext = attemptCtx
		tried = append(tried, attempt.ID)
		leaf, ok, class, err := n.launch(cfg, attempt)
		cancel()
		if ok && leaf != nil && leaf.Info().Up {
			return leaf, tried, failures
		}
		failures = append(failures, providerFailure(leaf, attempt.ID, class, err))
		if leaf != nil {
			_ = leaf.Close()
		}
	}
	return nil, tried, failures
}

func (n *networkSession) openGateway(ctx context.Context, leaf *session) (*session, error) {
	cfg := n.cfg
	cfg.providerOnly = false
	cfg.ProbeHost = ""
	cfg.startupContext = ctx
	provider := ProviderDesync
	if leaf != nil {
		provider = leaf.provider
		cfg.upstreamSOCKS = leaf.SocksAddr()
		cfg.ExcludeCIDRs = append(append([]string(nil), cfg.ExcludeCIDRs...), leaf.peerExclusions...)
	} else {
		cfg.upstreamSOCKS = ""
	}
	gateway, ok, class, err := n.launch(cfg, providerAttempt{ID: provider})
	if !ok || gateway == nil || !gateway.Info().Up {
		if gateway != nil {
			if gateway.child.Running() {
				gateway.exitOrigin = "cleanup"
			}
			_ = gateway.Close()
		}
		if err == nil {
			err = fmt.Errorf("network gateway not ready")
		}
		if class == "" || class == FailOK {
			class = FailDial
		}
		failure := providerFailure(gateway, provider, class, err)
		if failure.Stage == "" {
			failure.Stage = "readiness"
		}
		failure.Stage = "gateway_" + failure.Stage
		n.mu.Lock()
		n.failures = append(n.failures, failure)
		n.mu.Unlock()
		return nil, err
	}
	return gateway, nil
}

func (n *networkSession) recordControlFailure() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.leaf == nil {
		return
	}
	n.failures = append(n.failures, ProviderFailure{
		ProviderID: n.leaf.provider, Stage: "gateway_verification", Class: FailProbe,
		Controls:        append([]ControlResult(nil), n.controls...),
		GatewayControls: append([]ControlResult(nil), n.gatewayControls...),
	})
}

// CheckHealth updates provider health only from the configured control quorum.
// ProbeTLS remains available for diagnostics without changing this health state.
func (n *networkSession) CheckHealth(ctx context.Context) bool {
	n.mu.Lock()
	gateway, leaf, epoch, closed := n.gateway, n.leaf, n.epoch, n.closed
	cfg := n.cfg
	n.mu.Unlock()
	if closed || gateway == nil {
		return false
	}
	var results, gatewayResults []ControlResult
	healthy, gatewayHealthy := false, false
	var work sync.WaitGroup
	work.Add(1)
	go func() {
		defer work.Done()
		gatewayResults, gatewayHealthy = checkControls(ctx, cfg.ControlHosts, cfg.ControlQuorum, gateway.probeTLSContext)
	}()
	if leaf != nil {
		work.Add(1)
		go func() {
			defer work.Done()
			results, healthy = checkControls(ctx, cfg.ControlHosts, cfg.ControlQuorum, leaf.probeTLSContext)
		}()
	}
	work.Wait()
	if leaf == nil {
		results, healthy = gatewayResults, gatewayHealthy
	} else {
		healthy = healthy && gatewayHealthy
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.epoch != epoch || n.gateway != gateway || ctx.Err() != nil {
		return false
	}
	n.controls, n.gatewayControls, n.healthy = results, gatewayResults, healthy
	return healthy
}

func (n *networkSession) Info() Info {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.gateway == nil {
		return Info{Mode: "local", Coverage: "tls_http_only", Healthy: false}
	}
	info := n.gateway.Info()
	info.Mode, info.Coverage = "local", "tls_http_only"
	info.ProviderID = ProviderDesync
	if n.leaf != nil {
		info.Mode, info.Coverage = "remote", "public_tcp_udp_dual_stack"
		info.ProviderID = n.leaf.provider
		info.ProviderPID = n.leaf.Info().PID
		info.Up = info.Up && n.leaf.Info().Up
	}
	info.Up = info.Up && !n.closed
	info.Selective = false
	info.Healthy = n.healthy && info.Up
	info.Controls = append([]ControlResult(nil), n.controls...)
	info.GatewayControls = append([]ControlResult(nil), n.gatewayControls...)
	info.ControlQuorum = n.cfg.ControlQuorum
	info.Failures = append([]ProviderFailure(nil), n.failures...)
	info.ProvidersTried = append([]ProviderID(nil), n.tried...)
	info.TunnelHosts, info.DirectHosts = nil, nil
	info.LastProbe = FailProbe
	info.FailDetail = "control quorum unavailable"
	if info.Healthy {
		info.LastProbe, info.FailDetail = FailOK, ""
	}
	if len(n.controls) > 0 {
		info.LastProbeAt = n.controls[len(n.controls)-1].At
	}
	info.RetryHint = !info.Healthy || n.leaf == nil
	return info
}

func (n *networkSession) SocksAddr() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.gateway == nil {
		return ""
	}
	return n.gateway.SocksAddr()
}
func (n *networkSession) ProviderID() ProviderID { return n.Info().ProviderID }
func (n *networkSession) ProbeTLS(host string) FailSignal {
	n.mu.Lock()
	gateway, ctx := n.gateway, n.cfg.Context
	n.mu.Unlock()
	if gateway == nil {
		return FailSignal{Target: host, Class: FailDial, At: time.Now().UTC()}
	}
	return gateway.probeTLSContext(ctx, host)
}

// RefreshTransport keeps the gateway alive while checking candidates. A local
// gateway is replaced only after a remote candidate passes. Remote-to-remote
// failover changes the leaf listener without touching the gateway or TUN.
func (n *networkSession) RefreshTransport(ctx context.Context) error {
	n.refreshMu.Lock()
	defer n.refreshMu.Unlock()
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return context.Canceled
	}
	oldGateway, oldLeaf := n.gateway, n.leaf
	n.mu.Unlock()
	if oldLeaf != nil {
		_ = oldLeaf.Close()
	}
	trial, done := context.WithTimeout(ctx, networkStartupBudget)
	defer done()
	leaf, tried, failures := n.selectProvider(trial)
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		if leaf != nil {
			_ = leaf.Close()
		}
		return context.Canceled
	}
	n.tried = tried
	n.failures = append(n.failures, failures...)
	if len(n.failures) > 16 {
		n.failures = n.failures[len(n.failures)-16:]
	}
	n.mu.Unlock()
	if leaf == nil && oldLeaf == nil {
		return fmt.Errorf("remote control quorum unavailable")
	}
	if leaf != nil && oldLeaf != nil {
		n.mu.Lock()
		if n.closed {
			n.mu.Unlock()
			_ = leaf.Close()
			return context.Canceled
		}
		n.leaf = leaf
		n.epoch++
		n.controls = append([]ControlResult(nil), leaf.controls...)
		n.healthy = leaf.controlHealthy
		n.mu.Unlock()
		if !n.cfg.SkipStart && !n.CheckHealth(ctx) {
			return n.restoreLocalGateway()
		}
		return nil
	}
	// Promotion/demotion changes routing policy and needs one gateway restart.
	// Trials themselves never touched the active local adapter.
	if oldGateway != nil {
		_ = oldGateway.Close()
	}
	ready, finish := context.WithTimeout(n.cfg.Context, 8*time.Second)
	defer finish()
	healthContext := ready
	gateway, err := n.openGateway(ready, leaf)
	if err != nil && leaf != nil {
		_ = leaf.Close()
		leaf = nil
		fallback, stop := context.WithTimeout(n.cfg.Context, 8*time.Second)
		defer stop()
		healthContext = fallback
		gateway, err = n.openGateway(fallback, nil)
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		if gateway != nil {
			_ = gateway.Close()
		}
		if leaf != nil {
			_ = leaf.Close()
		}
		return context.Canceled
	}
	n.gateway, n.leaf = gateway, leaf
	n.epoch++
	n.healthy = false
	n.controls = nil
	n.mu.Unlock()
	if err != nil {
		return err
	}
	if !n.cfg.SkipStart {
		if !n.CheckHealth(healthContext) && leaf != nil {
			return n.restoreLocalGateway()
		}
	} else if leaf != nil {
		n.mu.Lock()
		n.controls = append([]ControlResult(nil), leaf.controls...)
		n.healthy = leaf.controlHealthy
		n.mu.Unlock()
	}
	if leaf == nil {
		return errors.New("remote unavailable; local gateway restored")
	}
	return nil
}

// A candidate is not adopted solely because its process started. Failed
// gateway verification restores limited routing with a fresh cleanup budget.
func (n *networkSession) restoreLocalGateway() error {
	n.recordControlFailure()
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return context.Canceled
	}
	gateway, leaf := n.gateway, n.leaf
	n.mu.Unlock()
	if gateway != nil {
		_ = gateway.Close()
	}
	if leaf != nil {
		_ = leaf.Close()
	}
	ctx, cancel := context.WithTimeout(n.cfg.Context, 8*time.Second)
	defer cancel()
	restored, err := n.openGateway(ctx, nil)
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		if restored != nil {
			_ = restored.Close()
		}
		return context.Canceled
	}
	n.gateway, n.leaf = restored, nil
	n.epoch++
	n.healthy, n.controls, n.gatewayControls = false, nil, nil
	n.mu.Unlock()
	if err != nil {
		return err
	}
	if !n.cfg.SkipStart {
		n.CheckHealth(ctx)
	}
	return errors.New("remote gateway controls failed; local gateway restored")
}

func (n *networkSession) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	n.epoch++
	n.cancel()
	gateway, leaf := n.gateway, n.leaf
	n.mu.Unlock()
	if gateway != nil {
		_ = gateway.Close()
	}
	if leaf != nil {
		_ = leaf.Close()
	}
	return nil
}
