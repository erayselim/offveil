package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

// Protection layers. DNS is always on while protection is on.
const (
	layerDNS       = "dns_only"  // no filtering measured: no TUN, no helper
	layerSelective = "selective" // TUN + local desync, groups may use a tunnel
	layerFallback  = "fallback"  // filtering measured but the TUN failed: DNS only
)

const (
	layerRetryInterval = 2 * time.Minute
	layerRetryBudget   = 3
)

type ipv4OnlySetter interface{ SetIPv4Only(bool) }

func (e *Engine) setIPv4OnlyLocked(on bool) {
	if setter, ok := e.dns.(ipv4OnlySetter); ok {
		setter.SetIPv4Only(on)
	}
}

func (e *Engine) recordStartupFailuresLocked(err error) {
	var startup *tunnel.StartupError
	if errors.As(err, &startup) {
		e.recordTunnelFailuresLocked("startup_attempt_failed", startup.Failures)
	}
}

// startLayer1Locked starts the helper, cleans a stale adapter, starts the
// selective gateway and waits for its adapter. Any failure leaves no helper
// or gateway behind so the caller can keep DNS-only protection.
func (e *Engine) startLayer1Locked(publish func(string)) error {
	e.lastLayerTry = time.Now()
	if publish == nil {
		publish = func(string) {}
	}
	capInfo := capture.Info{}
	if e.captureInfo != nil {
		capInfo = *e.captureInfo
	}
	resolve := e.resolveLocked()
	desCfg := desync.DefaultConfig()
	desCfg.Context, desCfg.ProbeHost, desCfg.Resolve = e.sessionContextLocked(), "", resolve
	strategy := desync.NativeSafeStrategy()
	if e.strategyStore != nil {
		if cached, found := e.strategyStore.Lookup(e.strategyScopeLocked()); found && desync.UsableOnOS(cached) {
			strategy = cached
		}
	}
	desCfg.Strategy = desync.PassThroughFirst(strategy)
	if e.job != nil {
		desCfg.AssignJob = e.job.Assign
	}
	desCfg.ConnIP = egressIPv4(&capInfo)
	if capInfo.Egress != nil {
		desCfg.BindInterface = capInfo.Egress.Name
	}
	publish("desync")
	des, err := e.startDesync(desCfg)
	if err != nil || des == nil || !des.Info().Up {
		if des != nil {
			_ = des.Close()
		}
		if err == nil {
			err = fmt.Errorf("helper not ready")
		}
		e.recordFailureLocked(diag.Failure{Component: "desync", Event: "unavailable", Reason: "startup"})
		return fmt.Errorf("desync: %w", err)
	}
	desInfo := des.Info()
	e.des, e.desyncConfig, e.desyncInfo = des, &desCfg, &desInfo

	tunCfg := tunnel.DefaultConfig()
	tunCfg.Selective, tunCfg.EnableTUN = true, true
	tunCfg.Context, tunCfg.Resolve = e.sessionContextLocked(), resolve
	if e.job != nil {
		tunCfg.AssignJob = e.job.Assign
	}
	tunCfg.ProbeHost, tunCfg.TunnelDomains, tunCfg.DirectDomains = "", nil, nil
	tunCfg.ControlHosts, tunCfg.ControlQuorum = e.controlHostsLocked(), 2
	tunCfg.TUNInterface, tunCfg.TUNAddress = capture.AdapterName, capture.TunIPv4
	tunCfg.Groups, tunCfg.GroupPaths = e.groupRoutesLocked(), e.groupPathsLocked()
	if e.rulesetSnap != nil {
		tunCfg.ExcludeSuffixes = e.rulesetSnap.Doc.ExcludeSuffixes()
	}
	tunCfg.DesyncSOCKS = des.SocksAddr()
	if capInfo.Egress != nil {
		tunCfg.EgressInterface = capInfo.Egress.Name
	}
	if e.dnsInfo != nil && e.dnsInfo.StubUp {
		tunCfg.DNSAddress = e.dnsInfo.ListenAddr
	}
	// A tunnel survives a gateway restart only if a group already uses it.
	if e.tunnelConfig != nil && e.tunnelConfig.TunnelProvider != "" {
		tunCfg.TunnelProvider, tunCfg.WARPProfile = e.tunnelConfig.TunnelProvider, e.tunnelConfig.WARPProfile
	}
	publish("tunnel")
	e.cleanOrphanLocked()
	session, err := e.startTunnel(tunCfg)
	if err != nil || session == nil || !session.Info().Up {
		if session != nil {
			_ = session.Close()
		}
		e.recordStartupFailuresLocked(err)
		if err == nil {
			err = fmt.Errorf("gateway not ready")
		}
		e.recordFailureLocked(diag.Failure{Component: "engine", Event: "layer_failed", Stage: "gateway_startup", Class: failureClass(err)})
		e.stopLayer1Locked()
		return err
	}
	e.tun, e.tunnelConfig = session, &tunCfg
	publish("adapter_attach")
	if err := e.attachLocked(session); err != nil {
		e.stopLayer1Locked()
		return fmt.Errorf("adapter readiness: %w", err)
	}
	info := session.Info()
	e.tunnelInfo = &info
	if !e.layerCleanup {
		e.layerCleanup = true
		e.cleanup.Register("layer", func() error {
			e.stopLayer1Locked()
			return nil
		})
	}
	e.layer, e.layerReason = layerSelective, ""
	e.setIPv4OnlyLocked(true)
	return nil
}

// stopLayer1Locked closes the gateway and helper; DNS stays up.
func (e *Engine) stopLayer1Locked() {
	if e.tun != nil {
		_ = e.tun.Close()
	}
	if e.des != nil {
		_ = e.des.Close()
	}
	e.tun, e.des = nil, nil
	e.tunnelInfo, e.desyncInfo = nil, nil
	e.tunnelConfig, e.desyncConfig = nil, nil
	e.setIPv4OnlyLocked(false)
}

// fallbackLocked keeps DNS protection when the TCP layer cannot start.
func (e *Engine) fallbackLocked(err error) {
	e.stopLayer1Locked()
	e.layer, e.layerReason = layerFallback, "tun_unavailable"
	e.recordFailureLocked(diag.Failure{Component: "engine", Event: "dns_only_fallback", Class: failureClass(err)})
}

func failureClass(err error) string {
	switch {
	case err == nil:
		return ""
	case isPrivilegeErr(err):
		return "permission"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "other"
}

// resolveLocked resolves public IPv4 endpoints through the session's DoH client.
func (e *Engine) resolveLocked() func(context.Context, string) (netip.Addr, error) {
	doh := e.doh
	return func(ctx context.Context, host string) (netip.Addr, error) {
		if doh == nil {
			return netip.Addr{}, fmt.Errorf("resolver unavailable")
		}
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
}
