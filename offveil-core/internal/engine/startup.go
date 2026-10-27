package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
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

// Startup builds layers bottom-up: DNS first, then a measurement of the
// physical network, then the TCP layer only if that network filters. A TCP
// layer that cannot start never takes the DNS layer down with it.
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
	e.layer, e.layerReason, e.layerRetries, e.layerCleanup = "", "", 0, false
	e.classification, e.lastClassify, e.reclassify = nil, time.Time{}, false
	e.groupWork, e.monitorRound, e.tunnelTrials, e.attachTook = false, 0, nil, ""
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
		class := failureClass(cause)
		if errors.Is(cause, context.Canceled) {
			class = "canceled"
		}
		e.recordFailureLocked(diag.Failure{Component: "engine", Event: "startup_failed", Reason: code, Stage: stage, Class: class})
		e.freezeSupportLocked()
		e.lastSupport.Notes = append(e.lastSupport.Notes, "Startup failed; sidecars describe the attempted stack before cleanup.")
		e.cleanup.Run("start_failed")
		e.cleanup.Clear()
		e.stopLayer1Locked()
		e.cap, e.dns = nil, nil
		e.captureInfo, e.dnsInfo = nil, nil
		e.dnsConfig = nil
		e.doh, e.job = nil, nil
		return e.statusLocked(), &ipc.RPCError{Code: code, Message: message}
	}
	job, err := proc.NewKillOnCloseJob()
	if err != nil {
		return fail(ipc.CodeEngineFailed, fmt.Errorf("job: %w", err))
	}
	e.job = job
	// Cleanup is LIFO: layer (gateway, helper), resolver, capture, then job.
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
	e.initGroupsLocked(rs.Doc)
	e.expandSeen = make(map[string]struct{})
	doh := offdns.NewDoHClient(offdns.DefaultPoisonSet().WithExtra(rs.Doc.PoisonIPs))
	e.doh = doh
	e.cleanup.Register("doh", func() error { doh.Close(); return nil })
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

	publish("classify")
	egress := ""
	if capInfo.Egress != nil {
		egress = capInfo.Egress.Name
	}
	e.directProbe = newDirectProbe(egress, e.resolveLocked())
	e.classifyNowLocked()

	if e.classification.DPI == DPINone {
		e.layer = layerDNS
	} else if err := e.startLayer1Locked(publish); err != nil {
		if errors.Is(err, context.Canceled) || e.sessionContextLocked().Err() != nil {
			return fail(ipc.CodeEngineFailed, err)
		}
		e.fallbackLocked(err)
	}
	now := time.Now().UTC()
	e.lastTransportRetry = now
	e.since, e.protection = &now, true
	e.state = StateActive
	e.refreshNetworkStatusLocked()
	e.startReprobeLoop()
	e.startReliabilityLocked()
	e.freezeSupportLocked()
	if os.Getenv("OFFVEIL_NETWORK_BG") != "0" {
		go e.monitorNetworkSession(e.sessionGeneration)
	}
	return e.statusLocked(), nil
}

// classifyNowLocked measures the physical network. It holds the lifecycle
// lock for at most classifyBudget; Status readers use the published snapshot.
func (e *Engine) classifyNowLocked() {
	classify := e.classify
	if classify == nil {
		classify = classifyNetwork
	}
	result := classify(e.sessionContextLocked(), e.directProbe, e.controlHostsLocked(), e.canaryGroupsLocked())
	e.applyClassificationLocked(result)
}

func (e *Engine) applyClassificationLocked(result Classification) {
	previous := ""
	if e.classification != nil {
		previous = e.classification.DPI
	}
	e.classification, e.lastClassify, e.reclassify = &result, time.Now(), false
	if result.DPI != previous {
		e.recordFailureLocked(diag.Failure{Component: "network", Event: "classified", Reason: result.DPI})
	}
	for _, check := range result.Checks {
		if g := e.groupLocked(check.Group); g != nil && e.layer != layerSelective {
			g.Checked, g.Class, g.CheckedAt = true, check.Class, result.CheckedAt
			g.OK = check.Class == string(tunnel.FailOK)
		}
	}
}
