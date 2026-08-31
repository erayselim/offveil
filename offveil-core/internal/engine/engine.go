package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/cleanup"
	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
	"github.com/erayselim/offveil/offveil-core/internal/policy"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
	"github.com/erayselim/offveil/offveil-core/internal/proc"
	"github.com/erayselim/offveil/offveil-core/internal/repair"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
	"github.com/erayselim/offveil/offveil-core/internal/udp"
	"github.com/erayselim/offveil/offveil-core/internal/version"
)

// State values match contracts.md Status.state.
const (
	StateStopped  = "stopped"
	StateStarting = "starting"
	StateActive   = "active"
	StateDegraded = "degraded"
	StateStopping = "stopping"
)

// CaptureStartFunc starts the TUN capture stack (overridable in tests).
type CaptureStartFunc func(capture.Config) (capture.Session, error)

// DNSStartFunc starts the DoH stub + leak guard (overridable in tests).
type DNSStartFunc func(offdns.Config) (offdns.Session, error)

// DesyncStartFunc starts the ByeDPI SOCKS sidecar (overridable in tests).
type DesyncStartFunc func(desync.Config) (desync.Session, error)

// TunnelStartFunc starts the selective tunnel outbound (overridable in tests).
type TunnelStartFunc func(tunnel.Config) (tunnel.Session, error)

// ProbeFunc runs session-start / test probes (overridable in tests).
type ProbeFunc func(ctx context.Context, doh *offdns.DoHClient, hosts []string) probe.Report

// NetInfoFunc looks up ASN + local fingerprint (overridable in tests).
type NetInfoFunc func(ctx context.Context) netinfo.Info

// RepairFunc runs leftover DNS/NRPT/adapter restore (overridable in tests).
type RepairFunc func() repair.Result

// Engine is the protection orchestrator.
type Engine struct {
	mu sync.Mutex

	state       string
	protection  bool
	summary     string
	since       *time.Time
	lastError   *string
	targets     []ipc.TargetStatus
	captureInfo *capture.Info
	dnsInfo     *offdns.Info
	desyncInfo  *desync.Info
	tunnelInfo  *tunnel.Info
	lastProbe   *probe.Report
	rulesetSnap *ruleset.Snapshot

	cleanup *cleanup.Registry
	job     *proc.Job
	cap     capture.Session
	dns     offdns.Session
	des     desync.Session
	tun     tunnel.Session
	policy  *policy.Store
	doh     *offdns.DoHClient

	startCapture CaptureStartFunc
	startDNS     DNSStartFunc
	startDesync  DesyncStartFunc
	startTunnel  TunnelStartFunc
	runProbe     ProbeFunc
	lookupNet    NetInfoFunc
	runRepair    RepairFunc
	loadRuleset  func(ctx context.Context) (ruleset.Snapshot, error)

	strategyStore *desync.StrategyStore
	scanDesync    desync.ScanFunc
	asnPathStore  *policy.ASNPathStore

	reprobeCancel context.CancelFunc
	lastCanaryAt  time.Time

	dataplaneTunnel []string

	// Legacy CDN / half-load domain expand.
	expandSeen        map[string]struct{}
	expandSuggestions []ruleset.Suggestion
	expandRoutesAdded int

	// Network change + power-resume self-heal.
	reliabilityCancel context.CancelFunc
	healMu            sync.Mutex
	lastHealAt        time.Time
	healCount         int
	healReason        string
	healAt            string
	healWatching      bool

	// Last active-session support snapshot (kept after Stop so diag stays useful).
	lastSupport *diag.Input
}

func New(reg *cleanup.Registry) *Engine {
	return &Engine{
		state:        StateStopped,
		summary:      "Kapalı",
		cleanup:      reg,
		policy:       policy.NewStore(),
		startCapture: capture.Start,
		startDNS:     offdns.Start,
		startDesync:  desync.Start,
		startTunnel:  tunnel.Start,
		targets: []ipc.TargetStatus{
			{ID: "discord", Label: "Discord", Outcome: "unknown", Path: "none"},
		},
	}
}

// WithCaptureStart overrides TUN bring-up (unit tests / dry-run without admin).
func (e *Engine) WithCaptureStart(fn CaptureStartFunc) *Engine {
	e.startCapture = fn
	return e
}

// WithDNSStart overrides DNS stub bring-up (unit tests).
func (e *Engine) WithDNSStart(fn DNSStartFunc) *Engine {
	e.startDNS = fn
	return e
}

// WithDesyncStart overrides ByeDPI bring-up (unit tests).
func (e *Engine) WithDesyncStart(fn DesyncStartFunc) *Engine {
	e.startDesync = fn
	return e
}

// WithTunnelStart overrides selective tunnel bring-up (unit tests).
func (e *Engine) WithTunnelStart(fn TunnelStartFunc) *Engine {
	e.startTunnel = fn
	return e
}

// WithProbe overrides session-start probing (unit tests).
func (e *Engine) WithProbe(fn ProbeFunc) *Engine {
	e.runProbe = fn
	return e
}

// WithNetInfo overrides ASN / fingerprint lookup (unit tests).
func (e *Engine) WithNetInfo(fn NetInfoFunc) *Engine {
	e.lookupNet = fn
	return e
}

// WithStrategyStore overrides ISS-keyed desync strategy persistence (unit tests).
func (e *Engine) WithStrategyStore(store *desync.StrategyStore) *Engine {
	e.strategyStore = store
	return e
}

// WithDesyncScan overrides limited blockcheck scanning (unit tests).
func (e *Engine) WithDesyncScan(fn desync.ScanFunc) *Engine {
	e.scanDesync = fn
	return e
}

// WithRepair overrides leftover network restore (unit tests).
func (e *Engine) WithRepair(fn RepairFunc) *Engine {
	e.runRepair = fn
	return e
}

// Start begins protection: Job + DoH + Wintun + DNS stub + ByeDPI desync.
func (e *Engine) Start(mode string) (*ipc.Status, *ipc.RPCError) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if mode != "" && mode != "auto" {
		return nil, &ipc.RPCError{Code: ipc.CodeBadRequest, Message: "only mode=auto is supported"}
	}
	switch e.state {
	case StateActive, StateStarting, StateDegraded:
		return e.statusLocked(), &ipc.RPCError{Code: ipc.CodeAlreadyRunning, Message: "protection already running"}
	case StateStopping:
		return nil, &ipc.RPCError{Code: ipc.CodeInternal, Message: "busy stopping"}
	}

	e.state = StateStarting
	e.lastError = nil
	e.captureInfo = nil
	e.dnsInfo = nil
	e.desyncInfo = nil
	e.tunnelInfo = nil
	slog.Info("engine: start", "mode", "auto")

	job, err := proc.NewKillOnCloseJob()
	if err != nil {
		e.state = StateStopped
		msg := fmt.Sprintf("job object: %v", err)
		e.lastError = &msg
		return e.statusLocked(), &ipc.RPCError{Code: ipc.CodeEngineFailed, Message: msg}
	}
	if e.job != nil {
		_ = e.job.Close()
	}
	e.job = job

	// Signed ruleset: cache → file → embedded; optional remote channel.
	loadRS := e.loadRuleset
	if loadRS == nil {
		loadRS = func(ctx context.Context) (ruleset.Snapshot, error) {
			return ruleset.Load(ctx, ruleset.LoadOptions{
				SkipRemote: os.Getenv("OFFVEIL_RULESET_SKIP_UPDATE") == "1",
			})
		}
	}
	rsCtx, rsCancel := context.WithTimeout(context.Background(), 10*time.Second)
	rs, rsErr := loadRS(rsCtx)
	rsCancel()
	if rsErr != nil {
		slog.Warn("engine: ruleset load failed, using embedded", "err", rsErr)
		rs = ruleset.MustLoadEmbedded()
	}
	e.rulesetSnap = &rs
	tunnelDomains := rs.Doc.TunnelDomains()
	directDomains := rs.Doc.DirectDomains()
	resolveHosts := rs.Doc.ResolveHosts()
	probeHosts := rs.Doc.ProbeHosts()
	targets := targetsFromDoc(rs.Doc)
	e.expandSeen = map[string]struct{}{}
	e.expandSuggestions = nil
	e.expandRoutesAdded = 0
	slog.Info("engine: ruleset", "source", rs.Source, "version", rs.Doc.Version,
		"tunnel", len(tunnelDomains), "direct", len(directDomains), "resolve", len(resolveHosts))

	// DoH for allowlist resolve; falls back to poison-filtered plain UDP.
	doh := offdns.NewDoHClient(offdns.DefaultPoisonSet())
	capCfg := capture.DefaultConfig()
	capCfg.SkipAdapter = true
	capCfg.ApplyRoutes = false
	if len(resolveHosts) > 0 {
		capCfg.ResolveHosts = resolveHosts
	}
	capCfg.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
		slog.Info("dns: resolving", "host", host)
		addrs, err := doh.LookupAWithFallback(ctx, host)
		if err != nil {
			slog.Warn("dns: resolve failed", "host", host, "err", err)
			return nil, err
		}
		slog.Info("dns: resolved", "host", host, "addrs", len(addrs))
		return addrs, nil
	}

	startFn := e.startCapture
	if startFn == nil {
		startFn = capture.Start
	}
	sess, err := startFn(capCfg)
	if err != nil {
		_ = e.job.Close()
		e.job = nil
		e.state = StateStopped
		msg := err.Error()
		e.lastError = &msg
		code := ipc.CodeTunFailed
		if isPrivilegeErr(err) {
			code = ipc.CodePrivilege
		}
		return e.statusLocked(), &ipc.RPCError{Code: code, Message: msg}
	}
	e.cap = sess
	info := sess.Info()
	e.captureInfo = &info

	poisonHost := "discord.com"
	if len(probeHosts) > 0 {
		poisonHost = probeHosts[0]
	}
	if _, poisonID, perr := offdns.ProbeSystemDNS(poisonHost, offdns.DefaultPoisonSet()); perr == nil && poisonID != "" {
		if len(targets) > 0 {
			targets[0].Outcome = "dns_poison"
		}
		slog.Warn("engine: system DNS poison detected", "host", poisonHost, "fingerprint", poisonID)
	}

	dnsCfg := offdns.DefaultConfig()
	dnsCfg.ApplyLeakGuard = false
	// Catch-all NRPT: every Windows DNS Client name hits the stub. Leak-guard
	// stays off (no NIC rewrite). TUN uses split-default for local desync; not full WARP.
	dnsCfg.NRPTSuffixes = []string{offdns.NRPTCatchAll}
	dnsCfg.OnQuery = func(host string) {
		if !e.expandCandidate(host) {
			return
		}
		go e.handleExpandQuery(host)
	}

	dnsStart := e.startDNS
	if dnsStart == nil {
		dnsStart = offdns.Start
	}
	dnsSess, err := dnsStart(dnsCfg)
	if err != nil {
		_ = sess.Close()
		e.cap = nil
		e.captureInfo = nil
		_ = e.job.Close()
		e.job = nil
		e.state = StateStopped
		msg := fmt.Sprintf("dns: %v", err)
		e.lastError = &msg
		code := ipc.CodeEngineFailed
		if isPrivilegeErr(err) {
			code = ipc.CodePrivilege
		}
		return e.statusLocked(), &ipc.RPCError{Code: code, Message: msg}
	}
	e.dns = dnsSess
	di := dnsSess.Info()
	e.dnsInfo = &di
	e.doh = doh

	if e.policy == nil {
		e.policy = policy.NewStore()
	}

	// ISS/ASN + local fingerprint → invalidate policy cache on change.
	netFn := e.lookupNet
	if netFn == nil {
		netFn = netinfo.Lookup
	}
	nctx, ncancel := context.WithTimeout(context.Background(), 4*time.Second)
	ni := netFn(nctx)
	ncancel()
	if inv := e.policy.ObserveNetwork(ni); inv {
		slog.Info("engine: policy cache invalidated", "asn", e.policy.ASN(), "fp", e.policy.Fingerprint())
	}

	// Session-start curated probe → domain → path cache.
	probeFn := e.runProbe
	if probeFn == nil {
		probeFn = defaultProbe
	}
	pctx, pcancel := context.WithTimeout(context.Background(), 6*time.Second)
	if len(probeHosts) == 0 {
		probeHosts = probe.CuratedHosts()
	}
	rep := probeFn(pctx, doh, probeHosts)
	pcancel()
	rep.ASN = e.policy.ASN()
	rep.ISPHint = e.policy.ISPHint()
	e.lastProbe = &rep

	// Probe updates the matching special package only — not the session outbound.
	if len(rep.Results) > 0 {
		for _, pr := range rep.Results {
			path := pr.Path
			if path == "" {
				path = probe.PathFor(pr.Class)
			}
			if pe, ok := e.policy.Lookup(pr.Target); ok && pe.Path != "" {
				path = probe.PreferPath(pe.Path, path)
			}
			e.policy.Put(pr.Target, path, string(pr.Class), "probe:session")
			applyProbeResult(targets, rs.Doc, pr.Target, string(pr.Class), path)
			slog.Info("engine: probe", "target", pr.Target, "class", pr.Class, "path", path,
				"confidence", pr.Confidence, "took", pr.Took)
		}
	}

	resolveOne := func(ctx context.Context, host string) (netip.Addr, error) {
		addrs, err := doh.LookupAWithFallback(ctx, host)
		if err != nil {
			return netip.Addr{}, err
		}
		for _, a := range addrs {
			if a.Is4() {
				return a, nil
			}
		}
		if len(addrs) == 0 {
			return netip.Addr{}, fmt.Errorf("no A records for %s", host)
		}
		return addrs[0], nil
	}

	probeHost := "discord.com"
	if len(probeHosts) > 0 {
		probeHost = probeHosts[0]
	}

	var dsi desync.Info
	asn := e.policy.ASN()
	store := e.strategyStore
	if store == nil {
		if s, err := desync.OpenStrategyStore(""); err == nil {
			store = s
			e.strategyStore = s
		} else {
			slog.Warn("engine: strategy store unavailable", "err", err)
		}
	}

	strat := desync.DefaultSafeStrategy()
	stratSource := "default"
	if store != nil {
		if cached, ok := store.Lookup(asn); ok {
			strat = cached
			stratSource = "asn-cache"
		}
	}

	desCfg := desync.DefaultConfig()
	desCfg.Strategy = strat
	desCfg.Sink = e.policy
	desCfg.AssignJob = e.job.Assign
	desCfg.Resolve = resolveOne
	desCfg.ProbeHost = probeHost
	desCfg.ConnIP = egressIPv4(e.captureInfo)

	desStart := e.startDesync
	if desStart == nil {
		desStart = desync.Start
	}
	desSess, err := desStart(desCfg)
	if err != nil {
		_ = dnsSess.Close()
		e.dns = nil
		e.dnsInfo = nil
		_ = sess.Close()
		e.cap = nil
		e.captureInfo = nil
		_ = e.job.Close()
		e.job = nil
		e.state = StateStopped
		msg := fmt.Sprintf("desync: %v", err)
		e.lastError = &msg
		return e.statusLocked(), &ipc.RPCError{Code: ipc.CodeEngineFailed, Message: msg}
	}
	e.des = desSess
	dsi = desSess.Info()
	e.desyncInfo = &dsi
	slog.Info("engine: desync started", "strategy", dsi.StrategyID, "source", stratSource, "probe", dsi.LastProbe)

	if dsi.LastProbe == desync.FailOK && store != nil {
		_ = store.Put(asn, strat, probeHost)
	}

	if dsi.LastProbe != "" && dsi.LastProbe != desync.FailOK {
		if store != nil && stratSource == "asn-cache" {
			_ = store.Delete(asn)
		}
		outcome := string(dsi.LastProbe)
		switch dsi.LastProbe {
		case desync.FailReset:
			outcome = "dpi_reset"
		case desync.FailSSLErr:
			outcome = "ssl_err"
		case desync.FailTimeout:
			outcome = "timeout"
		}
		setTarget(targets, "discord", policy.PathTunnel, outcome)
		slog.Info("engine: desync probe failed, Discord special → tunnel",
			"class", dsi.LastProbe, "strategy", dsi.StrategyID)
	}

	tunnelHosts, desyncUDP := splitSpecialHosts(rs.Doc, targets, e.policy)
	needTunnel := len(tunnelHosts) > 0
	tunCfg := tunnel.DefaultConfig()
	tunCfg.Sink = e.policy
	tunCfg.AssignJob = e.job.Assign
	tunCfg.Resolve = resolveOne
	tunCfg.EnableTUN = true
	tunCfg.TUNInterface = capture.AdapterName
	tunCfg.TUNAddress = capture.TunIPv4
	tunCfg.TUNMTU = capture.DefaultMTU
	tunCfg.RouteCIDRs = append([]string{}, tunnel.SplitDefaultCIDRs()...)
	tunCfg.DirectDomains = directDomains
	tunCfg.SpecialDomains = desyncUDP
	tunCfg.TunnelDomains = tunnelHosts
	tunCfg.DesyncSOCKS = dsi.SocksAddr
	if tunCfg.DesyncSOCKS == "" {
		tunCfg.DesyncSOCKS = "127.0.0.1:18080"
	}

	if needTunnel {
		tunCfg.AllowlistOutbound = "tunnel"
		tunCfg.ProbeHost = tunnelLivenessHost(rs.Doc, e.policy, probeHosts)
	} else {
		tunCfg.AllowlistOutbound = "desync"
		tunCfg.ProbeHost = ""
	}

	tunStart := e.startTunnel
	if tunStart == nil {
		tunStart = tunnel.Start
	}
	tunSess, terr := tunStart(tunCfg)
	if needTunnel && (terr != nil || tunSess == nil || !tunUp(tunSess)) {
		if terr != nil {
			slog.Warn("engine: special tunnel failed, falling back to desync dataplane", "err", terr)
		}
		setTarget(targets, "discord", policy.PathTunnel, "retry")
		tunCfg.AllowlistOutbound = "desync"
		tunCfg.SpecialDomains = append(append([]string{}, desyncUDP...), tunnelHosts...)
		tunCfg.TunnelDomains = nil
		tunCfg.ProbeHost = ""
		tunSess, terr = tunStart(tunCfg)
	}
	if terr != nil {
		msg := fmt.Sprintf("tunnel: %v", terr)
		e.lastError = &msg
		slog.Warn("engine: dataplane hard fail", "err", terr, "outbound", tunCfg.AllowlistOutbound)
	} else if tunSess != nil {
		e.tun = tunSess
		ti := tunSess.Info()
		e.tunnelInfo = &ti
		dataplaneOK := ti.Up && (ti.LastProbe == tunnel.FailOK || ti.LastProbe == "")
		if dataplaneOK {
			attachCaptureAdapter(e.cap, capture.AdapterName)
			if ti.ProviderID != tunnel.ProviderDesync && needTunnel {
				if targetPath(targets, "discord") == policy.PathTunnel {
					setTarget(targets, "discord", policy.PathTunnel, "ok")
				}
				if e.policy != nil && tunCfg.ProbeHost != "" {
					e.policy.OnTunnelOK(tunCfg.ProbeHost, string(ti.ProviderID))
				}
			}
			slog.Info("engine: TUN dataplane up", "provider", ti.ProviderID, "special_tunnel", needTunnel)
		} else if ti.RetryHint || !ti.Up {
			setTarget(targets, "discord", policy.PathTunnel, "retry")
		}
	}
	e.dataplaneTunnel = append([]string(nil), tunnelHosts...)

	for i := range targets {
		if targets[i].Path == "" || targets[i].Path == "none" {
			targets[i].Path = policy.PathDesync
			if targets[i].Outcome == "unknown" {
				targets[i].Outcome = "ok"
			}
		}
		if targets[i].Outcome == string(probe.ClassOpen) && targets[i].Path == policy.PathDirect {
			targets[i].Outcome = "ok"
		}
	}
	e.targets = targets

	e.cleanup.Register("sidecars", func() error {
		if e.tun != nil {
			_ = e.tun.Close()
			e.tun = nil
			e.tunnelInfo = nil
		}
		if e.des != nil {
			_ = e.des.Close()
			e.des = nil
			e.desyncInfo = nil
		}
		if e.job != nil {
			_ = e.job.Terminate(1)
			err := e.job.Close()
			e.job = nil
			return err
		}
		return nil
	})
	e.cleanup.Register("routes", func() error {
		slog.Info("cleanup: routes (via capture session)")
		return nil
	})
	e.cleanup.Register("adapter", func() error {
		sess := e.cap
		e.cap = nil
		e.captureInfo = nil
		if sess == nil {
			return nil
		}
		return sess.Close()
	})
	e.cleanup.Register("dns", func() error {
		sess := e.dns
		e.dns = nil
		e.dnsInfo = nil
		if sess == nil {
			return nil
		}
		return sess.Close()
	})

	now := time.Now().UTC()
	e.since = &now
	e.state = StateActive
	e.protection = true
	if e.tun != nil && e.tunnelInfo != nil && e.tunnelInfo.Up {
		e.summary = "Açık"
		e.state = StateActive
	} else {
		e.state = StateDegraded
		e.summary = "Bozuldu"
	}

	e.startReprobeLoop()
	e.startReliabilityLocked()
	e.freezeSupportLocked()
	if os.Getenv("OFFVEIL_CANARY_BG") != "0" {
		go e.probeCanary()
	}

	return e.statusLocked(), nil
}

// Stop ends protection and runs cleanup hooks.
func (e *Engine) Stop() (*ipc.Status, *ipc.RPCError) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.state == StateStopped {
		return e.statusLocked(), &ipc.RPCError{Code: ipc.CodeNotRunning, Message: "Core protection is stopped"}
	}

	e.state = StateStopping
	slog.Info("engine: stop")
	e.stopReliabilityLocked()
	e.stopReprobeLocked()
	e.cleanup.Run("stop")
	e.cleanup.Clear()

	e.state = StateStopped
	e.protection = false
	e.summary = "Kapalı"
	e.since = nil
	e.captureInfo = nil
	e.dnsInfo = nil
	e.desyncInfo = nil
	e.tunnelInfo = nil
	// Keep lastProbe + lastSupport for diagnostics after stop.
	e.doh = nil
	e.expandSeen = nil
	e.expandSuggestions = nil
	e.expandRoutesAdded = 0
	e.dataplaneTunnel = nil
	e.lastCanaryAt = time.Time{}
	e.targets = []ipc.TargetStatus{
		{ID: "discord", Label: "Discord", Outcome: "unknown", Path: "none"},
	}
	e.asnPathStore = nil // reopen on next Start (tests may change OFFVEIL_POLICY_CACHE)
	return e.statusLocked(), nil
}

// Repair stops protection if needed, restores leftover DNS/NRPT/adapter
// state, flushes the resolver cache, and clears learned DPI policy.
func (e *Engine) Repair() (*ipc.RepairResult, *ipc.RPCError) {
	st := e.Status()
	if st.Protection || st.State != StateStopped {
		if _, err := e.Stop(); err != nil && err.Code != ipc.CodeNotRunning {
			return &ipc.RepairResult{Status: e.Status()}, err
		}
	}

	fn := e.runRepair
	if fn == nil {
		fn = repair.Run
	}
	net := fn()

	e.mu.Lock()
	e.policy = policy.NewStore()
	e.strategyStore = nil
	e.asnPathStore = nil
	status := e.statusLocked()
	e.mu.Unlock()

	steps := make([]ipc.RepairStep, 0, len(net.Steps))
	for _, s := range net.Steps {
		steps = append(steps, ipc.RepairStep{Name: s.Name, OK: s.OK, Detail: s.Detail})
	}
	return &ipc.RepairResult{Status: status, Steps: steps}, nil
}

// CrashCleanup runs best-effort teardown (service stop, panic recovery, SIGINT).
func (e *Engine) CrashCleanup(reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	slog.Warn("engine: crash cleanup", "reason", reason, "state", e.state)
	e.stopReliabilityLocked()
	e.stopReprobeLocked()
	e.cleanup.Run(reason)
	e.cleanup.Clear()
	if e.des != nil {
		_ = e.des.Close()
		e.des = nil
	}
	if e.tun != nil {
		_ = e.tun.Close()
		e.tun = nil
	}
	if e.job != nil {
		_ = e.job.Close()
		e.job = nil
	}
	e.cap = nil
	e.captureInfo = nil
	e.dns = nil
	e.dnsInfo = nil
	e.desyncInfo = nil
	e.tunnelInfo = nil
	e.lastProbe = nil
	e.doh = nil
	e.state = StateStopped
	e.protection = false
	e.summary = "Kapalı"
	e.since = nil
}

// Status returns the current snapshot.
func (e *Engine) Status() *ipc.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.statusLocked()
}

// Health reports daemon liveness independent of protection state.
func (e *Engine) Health() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == StateDegraded {
		return "degraded"
	}
	return "ok"
}

// Test runs a short curated (or explicit) probe and refreshes the policy cache
// (contracts.md §2.2 / §4.3). Requires protection to be active.
func (e *Engine) Test(hosts []string) (*probe.Report, *ipc.RPCError) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.protection || e.state == StateStopped {
		return nil, &ipc.RPCError{Code: ipc.CodeNotRunning, Message: "Core protection is stopped"}
	}

	doh := e.doh
	if doh == nil {
		doh = offdns.NewDoHClient(offdns.DefaultPoisonSet())
	}
	probeFn := e.runProbe
	if probeFn == nil {
		probeFn = defaultProbe
	}
	if len(hosts) == 0 {
		if e.rulesetSnap != nil {
			hosts = append(e.rulesetSnap.Doc.ProbeHosts(), e.rulesetSnap.Doc.CanaryProbeHosts()...)
		}
		if len(hosts) == 0 {
			hosts = probe.CuratedHosts()
		}
	}

	netFn := e.lookupNet
	if netFn == nil {
		netFn = netinfo.Lookup
	}
	nctx, ncancel := context.WithTimeout(context.Background(), 4*time.Second)
	ni := netFn(nctx)
	ncancel()
	_ = e.policy.ObserveNetwork(ni)

	pctx, pcancel := context.WithTimeout(context.Background(), 10*time.Second)
	rep := probeFn(pctx, doh, hosts)
	pcancel()
	rep.ASN = e.policy.ASN()
	rep.ISPHint = e.policy.ISPHint()
	e.lastProbe = &rep

	for _, r := range rep.Results {
		path := r.Path
		if path == "" {
			path = probe.PathFor(r.Class)
		}
		if pe, ok := e.policy.Lookup(r.Target); ok && pe.Path != "" {
			path = probe.PreferPath(pe.Path, path)
		}
		e.policy.Put(r.Target, path, string(r.Class), "probe:test")
	}
	return &rep, nil
}

func defaultProbe(ctx context.Context, doh *offdns.DoHClient, hosts []string) probe.Report {
	return probe.Session(ctx, hosts, probe.Options{
		Timeout:     probe.DefaultTimeout,
		DoH:         doh,
		Poison:      offdns.DefaultPoisonSet(),
		VerifyHTTP:  false, // session-start stays within ~4s budget
		SkipControl: false,
	})
}

// startReprobeLoop silently refreshes expired per-domain cache entries (contracts §3.3).
func (e *Engine) startReprobeLoop() {
	e.stopReprobeLocked()
	ctx, cancel := context.WithCancel(context.Background())
	e.reprobeCancel = cancel
	go e.reprobeLoop(ctx)
}

func (e *Engine) stopReprobeLocked() {
	if e.reprobeCancel != nil {
		e.reprobeCancel()
		e.reprobeCancel = nil
	}
}

func (e *Engine) reprobeLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.silentReprobe()
			e.maybeCanary()
		}
	}
}

func (e *Engine) silentReprobe() {
	e.mu.Lock()
	if !e.protection || e.state == StateStopped || e.state == StateStopping {
		e.mu.Unlock()
		return
	}
	netFn := e.lookupNet
	if netFn == nil {
		netFn = netinfo.Lookup
	}
	expired := e.policy.ExpiredDomains()
	doh := e.doh
	probeFn := e.runProbe
	if probeFn == nil {
		probeFn = defaultProbe
	}
	hosts := expired
	e.mu.Unlock()

	// Backup to netwatch: ASN / fingerprint drift → self-heal.
	nctx, ncancel := context.WithTimeout(context.Background(), 4*time.Second)
	ni := netFn(nctx)
	ncancel()
	e.mu.Lock()
	inv := false
	if e.policy != nil {
		inv = e.policy.ObserveNetwork(ni)
	}
	e.mu.Unlock()
	if inv {
		slog.Info("engine: network identity changed during TTL loop")
		e.requestHeal("network_change")
		return
	}

	if len(hosts) == 0 {
		return
	}

	pctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	rep := probeFn(pctx, doh, hosts)
	cancel()

	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.protection {
		return
	}
	for _, r := range rep.Results {
		path := r.Path
		if path == "" {
			path = probe.PathFor(r.Class)
		}
		e.policy.Put(r.Target, path, string(r.Class), "probe:ttl")
		slog.Info("engine: silent re-probe", "target", r.Target, "class", r.Class, "path", path)
	}
}

func (e *Engine) statusLocked() *ipc.Status {
	var since *string
	if e.since != nil {
		s := e.since.Format(time.RFC3339)
		since = &s
	}
	targets := make([]ipc.TargetStatus, len(e.targets))
	copy(targets, e.targets)

	if e.dns != nil {
		di := e.dns.Info()
		e.dnsInfo = &di
	}
	if e.des != nil {
		dsi := e.des.Info()
		e.desyncInfo = &dsi
	}
	if e.tun != nil {
		ti := e.tun.Info()
		e.tunnelInfo = &ti
	}

	hint := ""
	if e.des != nil {
		hint = policy.PathDesync
	} else if e.tunnelInfo != nil && e.tunnelInfo.Up {
		if e.tunnelInfo.ProviderID == tunnel.ProviderDesync {
			hint = policy.PathDesync
		} else {
			hint = policy.PathTunnel
		}
	}
	discordPath := targetPath(targets, "discord")

	st := &ipc.Status{
		State:        e.state,
		Protection:   e.protection,
		Summary:      e.summary,
		OutboundHint: hint,
		Since:        since,
		Targets:      targets,
		LastError:    e.lastError,
		Health:       e.healthLocked(),
		Version:      version.Version,
		ContractsVer: version.ContractsVersion,
	}
	if e.captureInfo != nil {
		st.Capture = e.captureInfo
	}
	if e.dnsInfo != nil {
		st.DNS = e.dnsInfo
	}
	if e.desyncInfo != nil {
		st.Desync = e.desyncInfo
	}
	if e.tunnelInfo != nil {
		st.Tunnel = e.tunnelInfo
	}
	if e.rulesetSnap != nil {
		st.Ruleset = map[string]any{
			"version":    e.rulesetSnap.Doc.Version,
			"source":     e.rulesetSnap.Source,
			"updated_at": e.rulesetSnap.Doc.UpdatedAt,
			"sha256":     e.rulesetSnap.SHA256Hex,
			"packages":   len(e.rulesetSnap.Doc.Packages),
		}
	}
	if exp := e.expandInfoLocked(); exp != nil {
		st.Expand = exp
	}
	if e.protection {
		udpPath := hint
		if discordPath != "" && discordPath != "none" {
			udpPath = discordPath
		}
		st.UDP = udp.ForOutbound(udpPath)
	}
	if h := e.healInfoLocked(); h != nil {
		st.Heal = h
	}
	return st
}

func (e *Engine) healthLocked() string {
	if e.state == StateDegraded {
		return "degraded"
	}
	return "ok"
}

func isPrivilegeErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "access is denied") ||
		strings.Contains(msg, "access denied") ||
		strings.Contains(msg, "elevat") ||
		strings.Contains(msg, "privilege") {
		return true
	}
	var errno interface{ Errno() uintptr }
	if errors.As(err, &errno) {
		return errno.Errno() == 5 // ERROR_ACCESS_DENIED
	}
	return false
}

func attachCaptureAdapter(sess capture.Session, name string) {
	if sess == nil {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if err := sess.AttachAdapter(name); err == nil {
			return
		} else {
			last = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	if last != nil {
		slog.Warn("engine: attach dataplane adapter", "err", last, "name", name)
	}
}

func tunUp(s tunnel.Session) bool {
	if s == nil {
		return false
	}
	ti := s.Info()
	return ti.Up && (ti.LastProbe == tunnel.FailOK || ti.LastProbe == "")
}

func egressIPv4(info *capture.Info) string {
	if info == nil || info.Egress == nil {
		return ""
	}
	return info.Egress.IPv4
}

func splitSpecialHosts(doc ruleset.Document, targets []ipc.TargetStatus, pol *policy.Store) (tunnelHosts, desyncUDP []string) {
	for _, pkg := range doc.EnabledPackages() {
		if strings.EqualFold(pkg.PathForce, "direct") {
			continue
		}
		hosts := pkg.RouteHosts()
		if len(hosts) == 0 {
			continue
		}
		if pkg.IsCanary() {
			if canaryPackageWantsTunnel(pkg, pol) {
				tunnelHosts = append(tunnelHosts, hosts...)
			}
			continue
		}
		switch targetPath(targets, pkg.ID) {
		case policy.PathTunnel:
			tunnelHosts = append(tunnelHosts, hosts...)
		case policy.PathDirect:
			// Discord open: UDP stays ISS; TCP/443 still hits default desync.
		default:
			desyncUDP = append(desyncUDP, hosts...)
		}
	}
	return tunnelHosts, desyncUDP
}

func canaryPackageWantsTunnel(pkg ruleset.Package, pol *policy.Store) bool {
	if pol == nil {
		return false
	}
	for _, h := range pkg.ProbeHosts {
		if pe, ok := pol.Lookup(h); ok && pe.Path == policy.PathTunnel {
			return true
		}
	}
	return false
}

func tunnelLivenessHost(doc ruleset.Document, pol *policy.Store, fallback []string) string {
	for _, pkg := range doc.EnabledPackages() {
		if !pkg.IsCanary() {
			continue
		}
		for _, h := range pkg.ProbeHosts {
			if pol != nil {
				if pe, ok := pol.Lookup(h); ok && pe.Path == policy.PathTunnel {
					return h
				}
			}
		}
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	return "discord.com"
}

func sameHostSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, h := range a {
		seen[h]++
	}
	for _, h := range b {
		n, ok := seen[h]
		if !ok || n == 0 {
			return false
		}
		seen[h] = n - 1
	}
	return true
}
