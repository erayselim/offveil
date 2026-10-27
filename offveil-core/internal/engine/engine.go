package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
	// Immutable snapshots remain readable while any operation owns mu.
	operation atomic.Pointer[operationSnapshot]
	// Public lifecycle requests invalidate work from an older session.
	lifecycleGeneration uint64
	// Background work belongs to one accepted protection session, including
	// internal self-heal restarts. Public no-op requests do not replace it.
	sessionGeneration uint64
	sessionCtx        context.Context
	sessionCancel     context.CancelFunc

	state             string
	protection        bool
	summary           string
	since             *time.Time
	lastError         *string
	targets           []ipc.TargetStatus
	captureInfo       *capture.Info
	dnsInfo           *offdns.Info
	desyncInfo        *desync.Info
	tunnelInfo        *tunnel.Info
	lastProbe         *probe.Report
	desyncScan        *desync.ScanResult
	tunnelFallback    *tunnel.Info
	strategySwitching bool
	extraProbeHosts   []string
	rulesetSnap       *ruleset.Snapshot

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

	reprobeCancel context.CancelFunc
	// Bounded DNS demand count; hostnames never enter exported diagnostics.
	expandSeen map[string]struct{}

	// Network change + power-resume self-heal.
	reliabilityCancel  context.CancelFunc
	healMu             sync.Mutex
	lastHealAt         time.Time
	healCount          int
	healReason         string
	healAt             string
	healWatching       bool
	dnsConfig          *offdns.Config
	desyncConfig       *desync.Config
	tunnelConfig       *tunnel.Config
	recoveryAttempts   map[string]int
	lastRecovery       time.Time
	lastPathCheck      time.Time
	failureKey         string
	networkCheck       *NetworkHealth
	networkFailures    int
	lastTransportRetry time.Time
	networkFingerprint string // physical identity captured before installing TUN routes
	healing            bool

	// Last active-session support snapshot (kept after Stop so diag stays useful).
	lastSupport *diag.Input
}

func New(reg *cleanup.Registry) *Engine {
	e := &Engine{
		state:        StateStopped,
		summary:      "Kapalı",
		cleanup:      reg,
		policy:       policy.NewStore(),
		startCapture: capture.Start,
		startDNS:     offdns.Start,
		startDesync:  desync.Start,
		startTunnel:  tunnel.Start,
		targets:      networkTargets("none", false),
	}
	e.publishOperationLocked("")
	return e
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

// Start begins protection: Job + DoH + capture snapshot + DNS stub + ByeDPI + TUN dataplane.
func (e *Engine) Start(mode string) (*ipc.Status, *ipc.RPCError) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lifecycleGeneration++
	e.healing = false
	return e.startLocked(mode)
}

// Stop ends protection and runs cleanup hooks.
func (e *Engine) Stop() (*ipc.Status, *ipc.RPCError) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lifecycleGeneration++
	e.healing = false
	return e.stopLocked()
}

func (e *Engine) stopLocked() (*ipc.Status, *ipc.RPCError) {
	if e.state == StateStopped {
		return e.statusLocked(), &ipc.RPCError{Code: ipc.CodeNotRunning, Message: "Core protection is stopped"}
	}

	if e.protection {
		e.freezeSupportLocked()
	}
	e.state = StateStopping
	e.cancelSessionLocked()
	e.publishOperationLocked("cleanup")
	defer e.publishOperationLocked("")
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
	e.cap, e.dns, e.des, e.tun, e.job = nil, nil, nil, nil, nil
	e.expandSeen = nil
	e.targets = networkTargets("none", false)
	e.networkCheck = nil
	return e.statusLocked(), nil
}

// Repair stops protection if needed, restores leftover DNS/NRPT/adapter
// state, flushes the resolver cache, and clears learned DPI policy.
func (e *Engine) Repair() (*ipc.RepairResult, *ipc.RPCError) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lifecycleGeneration++
	e.healing = false
	if e.protection || e.state != StateStopped {
		if _, err := e.stopLocked(); err != nil && err.Code != ipc.CodeNotRunning {
			return &ipc.RepairResult{Status: e.statusLocked()}, err
		}
	}
	e.publishOperationLocked("repair")
	defer e.publishOperationLocked("")

	fn := e.runRepair
	if fn == nil {
		fn = repair.Run
	}
	net := fn()

	e.policy = policy.NewStore()
	e.strategyStore = nil
	status := e.statusLocked()

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
	e.lifecycleGeneration++
	e.healing = false
	e.cancelSessionLocked()
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
	if !e.mu.TryLock() {
		if snapshot := e.operation.Load(); snapshot != nil {
			return snapshot.statusCopy()
		}
		e.mu.Lock()
	}
	defer e.mu.Unlock()
	return e.statusLocked()
}

// Health reports daemon liveness independent of protection state.
func (e *Engine) Health() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.statusLocked().Health
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
	ctx, cancel := context.WithCancel(e.sessionContextLocked())
	e.reprobeCancel = cancel
	go e.reprobeLoop(ctx, e.sessionGeneration)
}

func (e *Engine) stopReprobeLocked() {
	if e.reprobeCancel != nil {
		e.reprobeCancel()
		e.reprobeCancel = nil
	}
}

func (e *Engine) reprobeLoop(ctx context.Context, generation uint64) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.silentReprobeSession(generation)
		}
	}
}

func (e *Engine) silentReprobe() {
	e.mu.Lock()
	generation := e.sessionGeneration
	e.mu.Unlock()
	e.silentReprobeSession(generation)
}

func (e *Engine) silentReprobeSession(generation uint64) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) {
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
	ctx := e.sessionContextLocked()
	e.mu.Unlock()

	// Relay egress ASN can change without a physical network change. It may
	// invalidate cached policy, but only the physical fingerprint needs rebind.
	nctx, ncancel := context.WithTimeout(ctx, 4*time.Second)
	ni := netFn(nctx)
	ncancel()
	e.mu.Lock()
	if !e.currentSessionLocked(generation) {
		e.mu.Unlock()
		return
	}
	if e.policy != nil {
		e.policy.ObserveNetwork(ni)
	}
	rebind := e.physicalNetworkChangedLocked(ni.Fingerprint)
	if rebind {
		e.resetDNSCacheLocked()
		// The change was already adopted above; do not require a second
		// ObserveNetwork call to rediscover it inside self-heal.
		e.requestHealLocked("network_change")
	}
	e.mu.Unlock()
	if rebind {
		slog.Info("engine: network identity changed during TTL loop")
		return
	}

	if len(hosts) == 0 {
		return
	}

	pctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	rep := probeFn(pctx, doh, hosts)
	cancel()

	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.currentSessionLocked(generation) {
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
	if e.protection && !e.strategySwitching {
		e.refreshNetworkStatusLocked()
	}
	if e.protection && (e.state == StateActive || e.state == StateDegraded) {
		component, failed, pid, exit := e.failedComponentLocked()
		if component != "" && e.componentRequiredLocked(component) {
			e.state, e.summary = StateDegraded, "Bozuldu"
			e.lastError = &failed
			key := fmt.Sprintf("%s:%d", component, pid)
			if e.failureKey != key {
				e.failureKey = key
				e.recordFailureLocked(diag.Failure{Component: component, Event: "unavailable", Exit: exit})
			}
		}
	}

	hint := ""
	if e.protection && e.tunnelInfo != nil && e.tunnelInfo.Up {
		if e.tunnelInfo.ProviderID == tunnel.ProviderDesync {
			hint = policy.PathDesync
		} else {
			hint = policy.PathTunnel
		}
	}

	targets := append([]ipc.TargetStatus(nil), e.targets...)
	var network *NetworkHealth
	if e.networkCheck != nil {
		value := *e.networkCheck
		value.BypassFamilies = append([]string(nil), value.BypassFamilies...)
		network = &value
	}
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
		Network:      network,
	}
	if e.healing {
		st.Transition = "network_heal"
	} else if e.strategySwitching {
		st.Transition = "transport_recovery"
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
		st.UDP = udp.ForOutbound(hint)
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
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "access is denied") ||
		strings.Contains(msg, "access denied") ||
		strings.Contains(msg, "elevat") ||
		strings.Contains(msg, "privilege") ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "requires root") ||
		strings.Contains(msg, "must be root") {
		return true
	}
	var errno interface{ Errno() uintptr }
	if errors.As(err, &errno) {
		return errno.Errno() == 5 // ERROR_ACCESS_DENIED
	}
	return false
}

func attachCaptureAdapter(parent context.Context, sess capture.Session, name string) error {
	if sess == nil {
		return fmt.Errorf("capture session unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	var last error
	for {
		if err := ctx.Err(); err != nil {
			if last != nil {
				return fmt.Errorf("%w: %v", err, last)
			}
			return err
		}
		if err := sess.AttachAdapter(name); err == nil {
			return nil
		} else {
			last = err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
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
