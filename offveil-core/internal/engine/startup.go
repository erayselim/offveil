package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/cleanup"
	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
	"github.com/erayselim/offveil/offveil-core/internal/policy"
	"github.com/erayselim/offveil/offveil-core/internal/proc"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

// Startup owns infrastructure, never an application's list of endpoints.
// Provider verification happens before the shared TUN is created. A working
// encrypted transport carries all public TCP/UDP, including opaque protocols.
func (e *Engine) startLocked(mode string) (*ipc.Status, *ipc.RPCError) {
	if mode != "" && mode != "auto" {
		return nil, &ipc.RPCError{Code: ipc.CodeBadRequest, Message: "only mode=auto is supported"}
	}
	switch e.state {
	case StateActive, StateStarting, StateDegraded:
		return e.statusLocked(), &ipc.RPCError{Code: ipc.CodeAlreadyRunning, Message: "protection already running"}
	case StateStopping:
		return nil, &ipc.RPCError{Code: ipc.CodeInternal, Message: "busy stopping"}
	}
	if e.cleanup == nil {
		e.cleanup = cleanup.NewRegistry()
	}
	e.state, e.summary = StateStarting, "Bağlanıyor"
	e.beginSessionLocked()
	e.lastError = nil
	e.lastProbe = nil
	e.failureKey = ""
	e.recoveryAttempts = make(map[string]int)
	e.lastRecovery, e.lastPathCheck = time.Time{}, time.Time{}
	e.desyncScan, e.tunnelFallback = nil, nil
	e.dnsConfig, e.desyncConfig, e.tunnelConfig = nil, nil, nil
	e.captureInfo, e.dnsInfo, e.desyncInfo, e.tunnelInfo = nil, nil, nil, nil
	e.networkFailures, e.lastTransportRetry = 0, time.Time{}
	e.networkCheck = nil
	e.targets = networkTargets("none", false)
	stage := "job"
	publish := func(next string) {
		stage = next
		e.publishOperationLocked(next)
	}
	publish(stage)
	defer e.publishOperationLocked("")
	defer func() {
		if !e.protection {
			e.cancelSessionLocked()
		}
	}()
	fail := func(code string, cause error) (*ipc.Status, *ipc.RPCError) {
		message := diag.Scrub(cause.Error())
		e.lastError = &message
		e.state, e.summary, e.protection = StateStopped, "Kapalı", false
		class := "other"
		switch {
		case isPrivilegeErr(cause):
			class = "permission"
		case errors.Is(cause, context.DeadlineExceeded):
			class = "timeout"
		case errors.Is(cause, context.Canceled):
			class = "canceled"
		}
		var startup *tunnel.StartupError
		if errors.As(cause, &startup) {
			e.recordTunnelFailuresLocked("startup_attempt_failed", startup.Failures)
			e.tunnelInfo = &tunnel.Info{Failures: append([]tunnel.ProviderFailure(nil), startup.Failures...)}
			if len(startup.Failures) > 0 {
				last := startup.Failures[len(startup.Failures)-1]
				stage, class = last.Stage, string(last.Class)
			}
		}
		e.recordFailureLocked(diag.Failure{Component: "engine", Event: "startup_failed", Reason: code, Stage: stage, Class: class})
		// Freeze the attempted stack before cleanup erases its evidence. Current
		// protection remains off; Up fields describe the attempted stack only.
		e.freezeSupportLocked()
		e.lastSupport.Notes = append(e.lastSupport.Notes, "Startup failed; sidecars describe the attempted stack before cleanup.")
		e.cleanup.Run("start_failed")
		e.cleanup.Clear()
		e.cap, e.dns, e.des, e.tun = nil, nil, nil, nil
		e.captureInfo, e.dnsInfo, e.desyncInfo, e.tunnelInfo = nil, nil, nil, nil
		e.dnsConfig, e.desyncConfig, e.tunnelConfig = nil, nil, nil
		e.doh, e.job = nil, nil
		return e.statusLocked(), &ipc.RPCError{Code: code, Message: message}
	}
	job, err := proc.NewKillOnCloseJob()
	if err != nil {
		return fail(ipc.CodeEngineFailed, fmt.Errorf("job: %w", err))
	}
	e.job = job
	// Cleanup is LIFO: gateway/provider, helper, resolver, capture, then job.
	e.cleanup.Register("job", func() error { return job.Close() })
	publish("ruleset")
	load := e.loadRuleset
	if load == nil {
		load = func(ctx context.Context) (ruleset.Snapshot, error) {
			return ruleset.Load(ctx, ruleset.LoadOptions{SkipRemote: os.Getenv("OFFVEIL_RULESET_SKIP_UPDATE") == "1"})
		}
	}
	rctx, cancel := context.WithTimeout(e.sessionContextLocked(), 10*time.Second)
	rs, err := load(rctx)
	cancel()
	if err != nil {
		slog.Warn("engine: ruleset unavailable, using embedded network policy", "err", err)
		rs = ruleset.MustLoadEmbedded()
	}
	e.rulesetSnap = &rs
	e.extraProbeHosts = append([]string(nil), rs.Doc.ProbeHosts()...)
	if len(e.extraProbeHosts) == 0 {
		e.extraProbeHosts = ruleset.DefaultControlHosts()
	}
	e.expandSeen = make(map[string]struct{})
	doh := offdns.NewDoHClient(offdns.DefaultPoisonSet())
	e.doh = doh
	e.cleanup.Register("doh", func() error { doh.Close(); return nil })
	resolve := func(ctx context.Context, host string) (netip.Addr, error) {
		addrs, err := doh.LookupAWithFallback(ctx, host)
		if err != nil {
			return netip.Addr{}, err
		}
		for _, addr := range addrs {
			if addr.Is4() {
				return addr, nil
			}
		}
		return netip.Addr{}, fmt.Errorf("no public A record for endpoint")
	}
	capCfg := capture.DefaultConfig()
	capCfg.SkipAdapter, capCfg.ApplyRoutes, capCfg.SplitDefault = true, false, true
	capCfg.ResolveHosts = nil
	capCfg.Resolve = doh.LookupAWithFallback
	publish("capture")
	startCapture := e.startCapture
	if startCapture == nil {
		startCapture = capture.Start
	}
	e.cap, err = startCapture(capCfg)
	if err != nil || e.cap == nil {
		if err == nil {
			err = fmt.Errorf("capture returned no session")
		}
		code := ipc.CodeTunFailed
		if isPrivilegeErr(err) {
			code = ipc.CodePrivilege
		}
		return fail(code, err)
	}
	capSession := e.cap
	e.cleanup.Register("capture", capSession.Close)
	capInfo := capSession.Info()
	e.captureInfo = &capInfo
	dnsCfg := offdns.DefaultConfig()
	dnsCfg.Client, dnsCfg.ApplyLeakGuard = doh, false
	dnsCfg.NRPTSuffixes = []string{offdns.NRPTCatchAll}
	// Observation never triggers speculative probes or sibling-host expansion.
	// It also never waits for the engine lock on a system DNS request.
	dnsCfg.OnQuery = e.observeDNSQuery
	e.dnsConfig = &dnsCfg
	publish("dns")
	startDNS := e.startDNS
	if startDNS == nil {
		startDNS = offdns.Start
	}
	e.dns, err = startDNS(dnsCfg)
	if err != nil || e.dns == nil {
		if err == nil {
			err = fmt.Errorf("resolver returned no session")
		}
		return fail(ipc.CodeEngineFailed, fmt.Errorf("dns: %w", err))
	}
	dnsSession := e.dns
	e.cleanup.Register("dns", func() error {
		if e.dns != nil {
			return e.dns.Close()
		}
		return nil
	})
	dnsInfo := dnsSession.Info()
	e.dnsInfo = &dnsInfo
	publish("network")
	lookup := e.lookupNet
	if lookup == nil {
		lookup = netinfo.Lookup
	}
	nctx, cancel := context.WithTimeout(e.sessionContextLocked(), 4*time.Second)
	identity := lookup(nctx)
	cancel()
	if e.policy == nil {
		e.policy = policy.NewStore()
	}
	e.policy.ObserveNetwork(identity)
	e.networkFingerprint = identity.Fingerprint
	if e.strategyStore == nil {
		if store, openErr := desync.OpenStrategyStore(""); openErr == nil {
			e.strategyStore = store
		}
	}

	// A helper is a fallback capability, not a mandatory dependency of a
	// healthy remote transport. No application or arbitrary host decides startup.
	desCfg := desync.DefaultConfig()
	desCfg.Context, desCfg.ProbeHost, desCfg.Resolve = e.sessionContextLocked(), "", resolve
	desCfg.Strategy, desCfg.AssignJob = desync.NativeSafeStrategy(), job.Assign
	if e.strategyStore != nil {
		if cached, found := e.strategyStore.Lookup(e.strategyScopeLocked()); found && desync.UsableOnOS(cached) {
			desCfg.Strategy = cached
		}
	}
	desCfg.ConnIP = egressIPv4(e.captureInfo)
	if capInfo.Egress != nil {
		desCfg.BindInterface = capInfo.Egress.Name
	}
	e.desyncConfig = &desCfg
	publish("desync")
	startDesync := e.startDesync
	if startDesync == nil {
		startDesync = desync.Start
	}
	e.des, err = startDesync(desCfg)
	if err != nil {
		e.recordFailureLocked(diag.Failure{Component: "desync", Event: "unavailable", Reason: "startup"})
	}
	if e.des != nil {
		desInfo := e.des.Info()
		e.desyncInfo = &desInfo
		e.cleanup.Register("desync", func() error {
			if e.des != nil {
				return e.des.Close()
			}
			return nil
		})
	}
	tunCfg := tunnel.DefaultConfig()
	tunCfg.NetworkMode, tunCfg.EnableTUN = true, true
	tunCfg.Context, tunCfg.AssignJob, tunCfg.Resolve = e.sessionContextLocked(), job.Assign, resolve
	tunCfg.ProbeHost, tunCfg.AllowlistOutbound = "", ""
	tunCfg.ControlHosts, tunCfg.ControlQuorum = append([]string(nil), e.extraProbeHosts...), 2
	tunCfg.TUNInterface, tunCfg.TUNAddress, tunCfg.TUNAddress6 = capture.AdapterName, capture.TunIPv4, capture.TunIPv6
	tunCfg.TUNMTU, tunCfg.RouteCIDRs = capture.DefaultMTU, tunnel.NetworkRouteCIDRs()
	tunCfg.TunnelDomains, tunCfg.SpecialDomains, tunCfg.DirectDomains = nil, nil, nil
	tunCfg.NetworkRoutes = rs.Doc.Network.Routes
	tunCfg.ProtectedDomains = nil
	tunCfg.DesyncSOCKS = "127.0.0.1:18080"
	if e.des != nil {
		tunCfg.DesyncSOCKS = e.des.SocksAddr()
	}
	if capInfo.Egress != nil {
		tunCfg.EgressInterface = capInfo.Egress.Name
	}
	if runtime.GOOS == "windows" && dnsInfo.StubUp {
		tunCfg.DNSAddress = dnsInfo.ListenAddr
	}
	e.tunnelConfig = &tunCfg
	publish("tunnel")
	startTunnel := e.startTunnel
	if startTunnel == nil {
		startTunnel = tunnel.Start
	}
	e.tun, err = startTunnel(tunCfg)
	if err != nil || e.tun == nil || !e.tun.Info().Up {
		if e.tun != nil {
			_ = e.tun.Close()
		}
		if err == nil {
			err = fmt.Errorf("network dataplane unavailable")
		}
		return fail(ipc.CodeTunFailed, err)
	}
	e.cleanup.Register("network", func() error {
		if e.tun != nil {
			return e.tun.Close()
		}
		return nil
	})
	ti := e.tun.Info()
	e.tunnelInfo = &ti
	e.recordTunnelFailuresLocked("startup_attempt_failed", ti.Failures)
	if ti.Mode == "remote" && !ti.Healthy {
		return fail(ipc.CodeEngineFailed, fmt.Errorf("network gateway failed independent connectivity controls"))
	}
	if e.networkModeLocked() == "local" && (e.des == nil || !e.des.Info().Up) {
		return fail(ipc.CodeEngineFailed, fmt.Errorf("remote transport unavailable and local fallback helper failed"))
	}
	publish("adapter_attach")
	if err = attachCaptureAdapter(e.sessionContextLocked(), e.cap, capture.AdapterName); err != nil {
		return fail(ipc.CodeTunFailed, fmt.Errorf("adapter readiness: %w", err))
	}
	attached := e.cap.Info()
	e.captureInfo = &attached
	now := time.Now().UTC()
	e.lastTransportRetry = now
	e.since, e.protection = &now, true
	e.refreshNetworkStatusLocked()
	e.startReprobeLoop()
	e.startReliabilityLocked()
	e.freezeSupportLocked()
	if os.Getenv("OFFVEIL_NETWORK_BG") != "0" {
		go e.monitorNetworkSession(e.sessionGeneration)
	}
	return e.statusLocked(), nil
}
