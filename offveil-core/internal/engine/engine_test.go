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

func classifier(dpi string) engine.ClassifyFunc {
	return func(context.Context, engine.DirectProbe, []string, []ruleset.CanaryGroup) engine.Classification {
		return engine.Classification{DPI: dpi, CheckedAt: "2026-10-27T00:00:00Z"}
	}
}

func gatewaySession() *tunnel.FakeSession {
	return tunnel.NewFakeSession(tunnel.Info{SocksAddr: "127.0.0.1:18081", ProviderID: tunnel.ProviderDesync, Mode: "selective", Up: true, Healthy: true})
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
		WithTunnelStart(func(tunnel.Config) (tunnel.Session, error) { return gatewaySession(), nil }).
		WithClassifier(classifier(engine.DPIPresent)).
		WithTunnelPrepare(func(context.Context, tunnel.Config, string) (tunnel.ProviderID, *tunnel.WARPProfile, []tunnel.EndpointTrial, error) {
			return "", nil, nil, errors.New("no tunnel in unit tests")
		}).
		WithAdapterCleanup(nil).WithSnapshot(nil).WithForcedLayer(func() bool { return false }).
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

func networkOf(t *testing.T, st *ipc.Status) *engine.NetworkHealth {
	t.Helper()
	health, ok := st.Network.(*engine.NetworkHealth)
	if !ok {
		t.Fatalf("network: %+v", st.Network)
	}
	return health
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
	if st.State != engine.StateActive || !st.Protection || st.OutboundHint != "desync" || st.Summary != "Açık" || eng.Health() != "ok" {
		t.Fatalf("active network: %+v", st)
	}
	if st.Capture == nil || st.DNS == nil || st.Tunnel == nil || st.Network == nil {
		t.Fatalf("missing infrastructure status: %+v", st)
	}
	requireNetworkTargets(t, st, "desync", "direct")
	if network := networkOf(t, st); network.Mode != "selective" || network.Layers.TCP != "up" || network.DPI != engine.DPIPresent || len(network.Groups) == 0 {
		t.Fatalf("layers: %+v", network)
	}
	if st.UDP == nil {
		t.Fatal("UDP policy missing")
	}
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

func TestStartupBuildsSelectiveGateway(t *testing.T) {
	var capCfg capture.Config
	var desCfg desync.Config
	var tunCfg tunnel.Config
	var dnsSession *offdns.FakeSession
	probeCalls := 0
	eng := newTestEngine(t).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			capCfg = cfg
			return capture.NewFakeSession(capture.Info{Egress: &capture.EgressInfo{Name: "Ethernet", IPv4: "192.0.2.10"}}), nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			dnsSession = offdns.NewFakeSession(offdns.Info{ListenAddr: cfg.ListenAddr})
			return dnsSession, nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			desCfg = cfg
			return desync.NewFakeSession(desync.Info{}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) { tunCfg = cfg; return gatewaySession(), nil }).
		WithProbe(func(context.Context, *offdns.DoHClient, []string) probe.Report { probeCalls++; return probe.Report{} })
	if _, rpcErr := eng.Start("auto"); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if !capCfg.SkipAdapter || !capCfg.SplitDefault || capCfg.ApplyRoutes {
		t.Fatalf("capture ownership: %+v", capCfg)
	}
	if !tunCfg.Selective || tunCfg.NetworkMode || !tunCfg.EnableTUN || tunCfg.TUNAddress != capture.TunIPv4 || tunCfg.TUNAddress6 != "" || len(tunCfg.RouteCIDRs) != 0 {
		t.Fatalf("selective TUN: %+v", tunCfg)
	}
	if tunCfg.TunnelProvider != "" || tunCfg.WARPProfile != nil {
		t.Fatal("startup must not prepare a tunnel")
	}
	doc := ruleset.MustLoadEmbedded().Doc
	if len(tunCfg.Groups) != len(doc.Canaries) || !reflect.DeepEqual(tunCfg.ExcludeSuffixes, doc.ExcludeSuffixes()) {
		t.Fatalf("groups=%d exclude=%d", len(tunCfg.Groups), len(tunCfg.ExcludeSuffixes))
	}
	if tunCfg.DNSAddress != "127.0.0.1:53" {
		t.Fatalf("gateway DNS must use the core stub on every platform: %q", tunCfg.DNSAddress)
	}
	if !desync.IsPassThrough(desCfg.Strategy) || desCfg.ConnIP != "192.0.2.10" || desCfg.BindInterface != "Ethernet" || tunCfg.EgressInterface != "Ethernet" {
		t.Fatalf("helper: %+v", desCfg)
	}
	if probeCalls != 0 || desCfg.ProbeHost != "" || tunCfg.ProbeHost != "" {
		t.Fatal("arbitrary destination classification affected startup")
	}
	if !dnsSession.IPv4Only() {
		t.Fatal("TCP layer must keep protected traffic on IPv4")
	}
}

func TestNoFilteringKeepsDNSLayerOnly(t *testing.T) {
	helpers, gateways := 0, 0
	var dnsSession *offdns.FakeSession
	eng := newTestEngine(t).WithClassifier(classifier(engine.DPINone)).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			dnsSession = offdns.NewFakeSession(offdns.Info{ListenAddr: cfg.ListenAddr})
			return dnsSession, nil
		}).
		WithDesyncStart(func(desync.Config) (desync.Session, error) {
			helpers++
			return desync.NewFakeSession(desync.Info{}), nil
		}).
		WithTunnelStart(func(tunnel.Config) (tunnel.Session, error) { gateways++; return gatewaySession(), nil })
	st, rpcErr := eng.Start("auto")
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if helpers != 0 || gateways != 0 || st.Tunnel != nil || st.Summary != "Açık" || st.OutboundHint != "direct" || dnsSession.IPv4Only() {
		t.Fatalf("unfiltered network got a TCP layer: helpers=%d gateways=%d status=%+v", helpers, gateways, st)
	}
	if network := networkOf(t, st); network.Mode != "dns_only" || network.Layers.DNS != "up" || network.Layers.TCP != "off" {
		t.Fatalf("layers: %+v", network)
	}
	requireNetworkTargets(t, st, "direct", "direct")
}

func TestForceFlagStartsTCPLayerOnAnUnfilteredNetwork(t *testing.T) {
	gateways := 0
	eng := newTestEngine(t).WithClassifier(classifier(engine.DPINone)).WithForcedLayer(func() bool { return true }).
		WithTunnelStart(func(tunnel.Config) (tunnel.Session, error) { gateways++; return gatewaySession(), nil })
	st, rpcErr := eng.Start("auto")
	if rpcErr != nil || gateways != 1 || networkOf(t, st).Mode != "selective" {
		t.Fatalf("forced layer: gateways=%d status=%+v err=%v", gateways, st, rpcErr)
	}
	// A measured offline network must not be overridden.
	off := newTestEngine(t).WithClassifier(classifier(engine.DPIOffline)).WithForcedLayer(func() bool { return true })
	if st, _ := off.Start("auto"); networkOf(t, st).Reason != engine.ReasonOffline {
		t.Fatalf("offline overridden: %+v", st)
	}
}

func TestGatewayFailureKeepsDNSProtection(t *testing.T) {
	helper := desync.NewFakeSession(desync.Info{})
	dnsSession := offdns.NewFakeSession(offdns.Info{ListenAddr: "127.0.0.1:53"})
	eng := newTestEngine(t).
		WithDNSStart(func(offdns.Config) (offdns.Session, error) { return dnsSession, nil }).
		WithDesyncStart(func(desync.Config) (desync.Session, error) { return helper, nil }).
		WithTunnelStart(func(tunnel.Config) (tunnel.Session, error) { return nil, errors.New("gateway unavailable") })
	st, rpcErr := eng.Start("auto")
	if rpcErr != nil {
		t.Fatalf("a TCP layer failure turned protection off: %v", rpcErr)
	}
	if !st.Protection || st.Summary != "Sınırlı koruma" || st.LastError != nil || st.State != engine.StateActive {
		t.Fatalf("fallback status: %+v", st)
	}
	if network := networkOf(t, st); network.Reason != engine.ReasonDNSOnly || network.Layers.TCP != "failed" || network.Layers.DNS != "up" {
		t.Fatalf("fallback layers: %+v", network)
	}
	if !helper.Closed() || !dnsSession.Info().StubUp || dnsSession.IPv4Only() {
		t.Fatal("fallback must close the helper and keep DNS")
	}
}

func TestHelperFailureKeepsDNSProtection(t *testing.T) {
	gateways := 0
	eng := newTestEngine(t).
		WithDesyncStart(func(desync.Config) (desync.Session, error) { return nil, errors.New("helper unavailable") }).
		WithTunnelStart(func(tunnel.Config) (tunnel.Session, error) { gateways++; return gatewaySession(), nil })
	st, rpcErr := eng.Start("auto")
	if rpcErr != nil || !st.Protection || gateways != 0 || networkOf(t, st).Reason != engine.ReasonDNSOnly {
		t.Fatalf("helper failure: status=%+v error=%v gateways=%d", st, rpcErr, gateways)
	}
}

func TestOfflineNetworkIsNotReportedAsBroken(t *testing.T) {
	eng := newTestEngine(t).WithClassifier(classifier(engine.DPIOffline))
	st, rpcErr := eng.Start("auto")
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if st.Summary != "Bağlantı yok" || st.State != engine.StateActive || st.LastError != nil || networkOf(t, st).Reason != engine.ReasonOffline {
		t.Fatalf("offline: %+v", st)
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

func TestDNSFailureStopsProtectionAndCleansUp(t *testing.T) {
	capSession := capture.NewFakeSession(capture.Info{})
	eng := newTestEngine(t).
		WithCaptureStart(func(capture.Config) (capture.Session, error) { return capSession, nil }).
		WithDNSStart(func(offdns.Config) (offdns.Session, error) { return nil, errors.New("port 53 busy") })
	st, rpcErr := eng.Start("auto")
	if rpcErr == nil || st.Protection || st.State != engine.StateStopped || !capSession.Closed() {
		t.Fatalf("DNS failure: status=%+v error=%v", st, rpcErr)
	}
	if !strings.Contains(*st.LastError, "port 53 busy") {
		t.Fatalf("error lost: %v", *st.LastError)
	}
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
