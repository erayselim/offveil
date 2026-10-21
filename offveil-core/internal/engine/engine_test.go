package engine_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/cleanup"
	"github.com/erayselim/offveil/offveil-core/internal/desync"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/engine"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
	"github.com/erayselim/offveil/offveil-core/internal/repair"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func fakeDiagnosticProbe(_ context.Context, _ *offdns.DoHClient, hosts []string) probe.Report {
	if len(hosts) == 0 {
		hosts = probe.ControlHosts()
	}
	rep := probe.Report{}
	for _, host := range hosts {
		rep.Results = append(rep.Results, probe.Result{Target: host, Class: probe.ClassOpen, Path: "direct", OK: true})
	}
	return rep
}

func fakeNet(context.Context) netinfo.Info {
	return netinfo.Info{ASN: "64512", ISPHint: "Fixture network", Fingerprint: "testfp"}
}

func remoteSession() *tunnel.FakeSession {
	return tunnel.NewFakeSession(tunnel.Info{SocksAddr: "127.0.0.1:18081", ProviderID: tunnel.ProviderWARP, Mode: "remote", Coverage: "public_tcp_udp_dual_stack", Up: true, Healthy: true, LastProbe: tunnel.FailOK})
}

func newTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	t.Setenv("OFFVEIL_RULESET_SKIP_UPDATE", "1")
	t.Setenv("OFFVEIL_DESYNC_CACHE", t.TempDir())
	t.Setenv("OFFVEIL_NETWORK_BG", "0")
	uniquePolicyCache(t)
	eng := engine.New(cleanup.NewRegistry()).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return capture.NewFakeSession(capture.Info{AdapterName: capture.AdapterName, Egress: &capture.EgressInfo{Name: "Ethernet", IfIndex: 12, IPv4: "192.0.2.10"}}), nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			return offdns.NewFakeSession(offdns.Info{ListenAddr: cfg.ListenAddr, LeakGuard: false}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			return desync.NewFakeSession(desync.Info{SocksAddr: "127.0.0.1:18080", StrategyID: cfg.Strategy.ID, Up: true}), nil
		}).
		WithTunnelStart(func(tunnel.Config) (tunnel.Session, error) { return remoteSession(), nil }).
		WithProbe(fakeDiagnosticProbe).WithNetInfo(fakeNet)
	t.Cleanup(func() { _, _ = eng.Stop() })
	return eng
}

func requireNetworkTargets(t *testing.T, st *ipc.Status, tcp, udp string) {
	t.Helper()
	if len(st.Targets) != 2 {
		t.Fatalf("network status targets: %+v", st.Targets)
	}
	for _, want := range []struct{ id, path string }{{"tcp", tcp}, {"udp", udp}} {
		found := false
		for _, target := range st.Targets {
			if target.ID == want.id {
				found = true
				if target.Path != want.path {
					t.Fatalf("%s path=%s want %s", want.id, target.Path, want.path)
				}
			}
		}
		if !found {
			t.Fatalf("missing %s target: %+v", want.id, st.Targets)
		}
	}
}

func TestStartStopStatus(t *testing.T) {
	eng := newTestEngine(t)
	if st := eng.Status(); st.State != engine.StateStopped || st.Protection {
		t.Fatalf("initial: %+v", st)
	}
	st, rpcErr := eng.Start("auto")
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if st.State != engine.StateActive || !st.Protection || st.OutboundHint != "tunnel" || eng.Health() != "ok" {
		t.Fatalf("active network: %+v", st)
	}
	if st.Capture == nil || st.DNS == nil || st.Tunnel == nil || st.Network == nil {
		t.Fatalf("missing infrastructure status: %+v", st)
	}
	requireNetworkTargets(t, st, "tunnel", "tunnel")
	if _, rpcErr := eng.Start("auto"); rpcErr == nil || rpcErr.Code != ipc.CodeAlreadyRunning {
		t.Fatalf("already_running: %v", rpcErr)
	}
	st, rpcErr = eng.Stop()
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if st.State != engine.StateStopped || st.Protection {
		t.Fatalf("stopped: %+v", st)
	}
	if _, rpcErr := eng.Stop(); rpcErr == nil || rpcErr.Code != ipc.CodeNotRunning {
		t.Fatalf("not_running: %v", rpcErr)
	}
}

func TestStartUsesCatchAllNRPT(t *testing.T) {
	var got offdns.Config
	eng := newTestEngine(t).WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
		got = cfg
		return offdns.NewFakeSession(offdns.Info{ListenAddr: cfg.ListenAddr, NRPT: true}), nil
	})
	if _, rpcErr := eng.Start("auto"); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if got.ApplyLeakGuard || !reflect.DeepEqual(got.NRPTSuffixes, []string{offdns.NRPTCatchAll}) {
		t.Fatalf("resolver steering: %+v", got)
	}
	if !reflect.DeepEqual(offdns.NRPTNamespaces(got.NRPTSuffixes), []string{"."}) {
		t.Fatal("catch-all namespace missing")
	}
	if got.OnQuery == nil {
		t.Fatal("DNS observation hook missing")
	}
	got.OnQuery("requested.example.test")
	got.OnQuery("1.2.3.4.in-addr.arpa")
}

func TestStartupUsesDualStackTransportAndIndependentControls(t *testing.T) {
	var capCfg capture.Config
	var desCfg desync.Config
	var tunCfg tunnel.Config
	probeCalls := 0
	eng := newTestEngine(t).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			capCfg = cfg
			return capture.NewFakeSession(capture.Info{Egress: &capture.EgressInfo{Name: "Ethernet", IPv4: "192.0.2.10"}}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			desCfg = cfg
			return desync.NewFakeSession(desync.Info{}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) { tunCfg = cfg; return remoteSession(), nil }).
		WithProbe(func(context.Context, *offdns.DoHClient, []string) probe.Report { probeCalls++; return probe.Report{} })
	if _, rpcErr := eng.Start("auto"); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if !capCfg.SkipAdapter || !capCfg.SplitDefault || capCfg.ApplyRoutes {
		t.Fatalf("capture ownership: %+v", capCfg)
	}
	if !tunCfg.NetworkMode || !tunCfg.EnableTUN || tunCfg.TUNAddress != capture.TunIPv4 || tunCfg.TUNAddress6 != capture.TunIPv6 {
		t.Fatalf("network TUN: %+v", tunCfg)
	}
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		if !strings.Contains(strings.Join(tunCfg.RouteCIDRs, ","), prefix) {
			t.Fatalf("missing public route %s: %v", prefix, tunCfg.RouteCIDRs)
		}
	}
	if desCfg.ConnIP != "192.0.2.10" || desCfg.BindInterface != "Ethernet" || tunCfg.EgressInterface != "Ethernet" {
		t.Fatal("physical egress bindings differ")
	}
	if probeCalls != 0 || desCfg.ProbeHost != "" || tunCfg.ProbeHost != "" {
		t.Fatal("arbitrary destination classification affected startup")
	}
	if !reflect.DeepEqual(tunCfg.ControlHosts, ruleset.DefaultControlHosts()) || tunCfg.ControlQuorum != 2 {
		t.Fatalf("network controls: %v quorum=%d", tunCfg.ControlHosts, tunCfg.ControlQuorum)
	}
	if len(tunCfg.TunnelDomains)+len(tunCfg.SpecialDomains)+len(tunCfg.DirectDomains)+len(tunCfg.ProtectedDomains) > 0 {
		t.Fatal("default transport contains destination-specific rules")
	}
}

func TestCrashCleanup(t *testing.T) {
	eng := newTestEngine(t)
	if _, rpcErr := eng.Start("auto"); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	eng.CrashCleanup("fixture")
	if st := eng.Status(); st.State != engine.StateStopped || st.Protection {
		t.Fatalf("crash cleanup: %+v", st)
	}
}

func TestRepairStopsProtection(t *testing.T) {
	eng := newTestEngine(t).WithRepair(func() repair.Result {
		return repair.Result{Steps: []repair.Step{{Name: "policy", OK: true, Detail: "cleared"}}}
	})
	if _, rpcErr := eng.Start("auto"); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	for range 2 {
		result, rpcErr := eng.Repair()
		if rpcErr != nil {
			t.Fatal(rpcErr)
		}
		if result.Status == nil || result.Status.Protection || result.Status.State != engine.StateStopped {
			t.Fatalf("repair: %+v", result)
		}
		if len(result.Steps) != 1 || result.Steps[0].Name != "policy" || !result.Steps[0].OK {
			t.Fatalf("repair steps: %+v", result.Steps)
		}
	}
}

func TestBadMode(t *testing.T) {
	if _, rpcErr := newTestEngine(t).Start("manual"); rpcErr == nil || rpcErr.Code != ipc.CodeBadRequest {
		t.Fatalf("bad_request: %v", rpcErr)
	}
}

func TestStartPrivilegeAndTunFailed(t *testing.T) {
	for _, tc := range []struct{ message, code string }{{"privilege: TUN requires root", ipc.CodePrivilege}, {"configure tun interface: failed", ipc.CodeTunFailed}} {
		eng := newTestEngine(t).WithCaptureStart(func(capture.Config) (capture.Session, error) { return nil, errors.New(tc.message) })
		if _, rpcErr := eng.Start("auto"); rpcErr == nil || rpcErr.Code != tc.code {
			t.Fatalf("%s: %v", tc.code, rpcErr)
		}
		if st := eng.Status(); st.Protection || st.State != engine.StateStopped {
			t.Fatalf("failed startup retained resources: %+v", st)
		}
	}
}

func TestOptionalHelperStartupFailureKeepsRemoteProtection(t *testing.T) {
	eng := newTestEngine(t).WithDesyncStart(func(desync.Config) (desync.Session, error) { return nil, errors.New("optional helper failed") })
	st, rpcErr := eng.Start("auto")
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if st.State != engine.StateActive || st.OutboundHint != "tunnel" || st.LastError != nil {
		t.Fatalf("optional helper broke transport: %+v", st)
	}
	requireNetworkTargets(t, st, "tunnel", "tunnel")
}

func TestOptionalHelperExitDoesNotRewriteRemoteStatus(t *testing.T) {
	helper := desync.NewFakeSession(desync.Info{})
	eng := newTestEngine(t).WithDesyncStart(func(desync.Config) (desync.Session, error) { return helper, nil })
	if _, rpcErr := eng.Start("auto"); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	_ = helper.Close()
	st := eng.Status()
	if st.State != engine.StateActive || st.OutboundHint != "tunnel" || st.LastError != nil {
		t.Fatalf("remote transport depended on exited helper: %+v", st)
	}
}

func TestLocalFallbackReportsLimitedCoverage(t *testing.T) {
	eng := newTestEngine(t).WithTunnelStart(func(tunnel.Config) (tunnel.Session, error) {
		return tunnel.NewFakeSession(tunnel.Info{Mode: "local", ProviderID: tunnel.ProviderDesync, Up: true, Healthy: true, LastProbe: tunnel.FailOK}), nil
	})
	st, rpcErr := eng.Start("auto")
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if st.State != engine.StateDegraded || st.Summary != "Sınırlı koruma" || st.OutboundHint != "desync" {
		t.Fatalf("local fallback claimed complete coverage: %+v", st)
	}
	requireNetworkTargets(t, st, "desync", "direct")
	health, ok := st.Network.(*engine.NetworkHealth)
	if !ok || health.Mode != "local" || health.Coverage != "tls_http_only" {
		t.Fatalf("coverage: %+v", st.Network)
	}
}

func TestUnavailableNetworkCleansUpStartupResources(t *testing.T) {
	capSession := capture.NewFakeSession(capture.Info{})
	dnsSession := offdns.NewFakeSession(offdns.Info{ListenAddr: "127.0.0.1:53"})
	helper := desync.NewFakeSession(desync.Info{})
	eng := newTestEngine(t).
		WithCaptureStart(func(capture.Config) (capture.Session, error) { return capSession, nil }).
		WithDNSStart(func(offdns.Config) (offdns.Session, error) { return dnsSession, nil }).
		WithDesyncStart(func(desync.Config) (desync.Session, error) { return helper, nil }).
		WithTunnelStart(func(tunnel.Config) (tunnel.Session, error) { return nil, errors.New("gateway unavailable") })
	st, rpcErr := eng.Start("auto")
	if rpcErr == nil || rpcErr.Code != ipc.CodeTunFailed || st.Protection || st.State != engine.StateStopped {
		t.Fatalf("failed gateway: status=%+v error=%v", st, rpcErr)
	}
	if !capSession.Closed() || dnsSession.Info().StubUp || !helper.Closed() {
		t.Fatal("failed startup left capture, DNS, or helper alive")
	}
}

func TestRunningProcessWithoutVerifiedNetworkCannotBecomeActive(t *testing.T) {
	eng := newTestEngine(t).WithTunnelStart(func(tunnel.Config) (tunnel.Session, error) {
		return tunnel.NewFakeSession(tunnel.Info{Mode: "remote", ProviderID: tunnel.ProviderWARP, Up: true, Healthy: false, LastProbe: tunnel.FailTimeout}), nil
	})
	status, rpcErr := eng.Start("auto")
	if rpcErr == nil || status.Protection || status.State != engine.StateStopped {
		t.Fatalf("process liveness was mistaken for verified connectivity: status=%+v error=%v", status, rpcErr)
	}
}

func TestLocalFallbackRequiresItsHelper(t *testing.T) {
	eng := newTestEngine(t).
		WithDesyncStart(func(desync.Config) (desync.Session, error) { return nil, errors.New("helper unavailable") }).
		WithTunnelStart(func(tunnel.Config) (tunnel.Session, error) {
			return tunnel.NewFakeSession(tunnel.Info{Mode: "local", ProviderID: tunnel.ProviderDesync, Up: true, Healthy: true}), nil
		})
	st, rpcErr := eng.Start("auto")
	if rpcErr == nil || st.Protection || st.State != engine.StateStopped {
		t.Fatalf("unusable local fallback accepted: status=%+v error=%v", st, rpcErr)
	}
}

func TestProviderFailoverAppliesToWholeNetwork(t *testing.T) {
	calls := 0
	eng := newTestEngine(t).WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
		calls++
		if !cfg.NetworkMode || len(cfg.TunnelDomains) > 0 {
			t.Fatal("provider failover remained destination-selective")
		}
		return tunnel.NewFakeSession(tunnel.Info{Mode: "remote", ProviderID: tunnel.ProviderReality, Up: true, Healthy: true, LastProbe: tunnel.FailOK, FailoverFrom: tunnel.ProviderWARP, ProvidersTried: []tunnel.ProviderID{tunnel.ProviderWARP, tunnel.ProviderReality}}), nil
	})
	st, rpcErr := eng.Start("auto")
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if calls != 1 || st.State != engine.StateActive || st.OutboundHint != "tunnel" {
		t.Fatalf("provider failover: %+v", st)
	}
	requireNetworkTargets(t, st, "tunnel", "tunnel")
}

func TestConnectionTestIsDiagnosticOnly(t *testing.T) {
	eng := newTestEngine(t)
	if _, rpcErr := eng.Test(nil); rpcErr == nil || rpcErr.Code != ipc.CodeNotRunning {
		t.Fatalf("not_running: %v", rpcErr)
	}
	if _, rpcErr := eng.Start("auto"); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	before := eng.Status()
	for _, class := range []probe.Class{probe.ClassOpen, probe.ClassDPIReset, probe.ClassIPDrop, probe.ClassTimeout} {
		var got []string
		eng.WithProbe(func(_ context.Context, _ *offdns.DoHClient, hosts []string) probe.Report {
			got = append([]string(nil), hosts...)
			return probe.Report{Results: []probe.Result{{Target: hosts[0], Class: class, Path: probe.PathFor(class), OK: true}}}
		})
		report, rpcErr := eng.Test([]string{"requested.example.test"})
		if rpcErr != nil {
			t.Fatal(rpcErr)
		}
		if report.ASN != "64512" || len(report.Results) != 1 || !reflect.DeepEqual(got, []string{"requested.example.test"}) {
			t.Fatalf("diagnostic result: %+v hosts=%v", report, got)
		}
		after := eng.Status()
		if before.State != after.State || before.OutboundHint != after.OutboundHint || before.Summary != after.Summary || !reflect.DeepEqual(before.Targets, after.Targets) {
			t.Fatalf("diagnostic class %s changed network: before=%+v after=%+v", class, before, after)
		}
	}
}

func TestDefaultConnectionTestUsesOnlyIndependentControls(t *testing.T) {
	eng := newTestEngine(t)
	if _, rpcErr := eng.Start("auto"); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	var got []string
	eng.WithProbe(func(ctx context.Context, doh *offdns.DoHClient, hosts []string) probe.Report {
		got = append([]string(nil), hosts...)
		return fakeDiagnosticProbe(ctx, doh, hosts)
	})
	if _, rpcErr := eng.Test(nil); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if !reflect.DeepEqual(got, ruleset.DefaultControlHosts()) {
		t.Fatalf("default controls: %v", got)
	}
}
