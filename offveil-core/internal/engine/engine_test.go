package engine_test

import (
	"context"
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
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func fakeDesyncProbe(_ context.Context, _ *offdns.DoHClient, hosts []string) probe.Report {
	if len(hosts) == 0 {
		hosts = probe.CuratedHosts()
	}
	rep := probe.Report{Results: make([]probe.Result, 0, len(hosts))}
	for _, h := range hosts {
		rep.Results = append(rep.Results, probe.Result{
			Target: h,
			Class:  probe.ClassDPIReset,
			Path:   "desync",
			OK:     true,
		})
	}
	return rep
}

func fakeNet(_ context.Context) netinfo.Info {
	return netinfo.Info{ASN: "9121", ISPHint: "Turk Telekom", Fingerprint: "testfp"}
}

func newTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	t.Setenv("OFFVEIL_RULESET_SKIP_UPDATE", "1")
	t.Setenv("OFFVEIL_DESYNC_CACHE", t.TempDir())
	uniquePolicyCache(t)
	store, err := desync.OpenStrategyStore("")
	if err != nil {
		t.Fatal(err)
	}
	reg := cleanup.NewRegistry()
	return engine.New(reg).
		WithStrategyStore(store).
		WithDesyncScan(func(ctx context.Context, cfg desync.ScanConfig) desync.ScanResult {
			return desync.ScanResult{OK: false, Reason: "test-skip"}
		}).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return capture.NewFakeSession(capture.Info{
				AdapterName:   capture.AdapterName,
				RoutesApplied: 2,
				RoutePrefixes: []string{"1.2.3.4/32", "5.6.7.8/32"},
				Egress:        &capture.EgressInfo{Name: "Ethernet", IfIndex: 12},
			}), nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			return offdns.NewFakeSession(offdns.Info{
				ListenAddr: cfg.ListenAddr,
				LeakGuard:  false,
			}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			id := desync.DefaultSafeStrategy().ID
			if cfg.Strategy.ID != "" {
				id = cfg.Strategy.ID
			}
			return desync.NewFakeSession(desync.Info{
				SocksAddr:  "127.0.0.1:18080",
				StrategyID: id,
				Up:         true,
				LastProbe:  desync.FailOK,
			}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
			pid := tunnel.ProviderWARP
			if cfg.AllowlistOutbound == "desync" {
				pid = tunnel.ProviderDesync
			}
			return tunnel.NewFakeSession(tunnel.Info{
				SocksAddr:  "127.0.0.1:18081",
				ProviderID: pid,
				Up:         true,
				LastProbe:  tunnel.FailOK,
			}), nil
		}).
		WithProbe(fakeDesyncProbe).
		WithNetInfo(fakeNet)
}

func TestStartStopStatus(t *testing.T) {
	eng := newTestEngine(t)

	st := eng.Status()
	if st.State != engine.StateStopped || st.Protection {
		t.Fatalf("initial: %+v", st)
	}

	st, err := eng.Start("auto")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if st.State != engine.StateActive || !st.Protection {
		t.Fatalf("after start: %+v", st)
	}
	if st.Capture == nil {
		t.Fatal("expected capture info on status")
	}
	if st.DNS == nil {
		t.Fatal("expected dns info on status")
	}
	if st.Desync == nil {
		t.Fatal("expected desync info on status")
	}
	if st.OutboundHint != "desync" {
		t.Fatalf("outbound_hint=%q want desync", st.OutboundHint)
	}
	if eng.Health() != "ok" {
		t.Fatalf("health=%s", eng.Health())
	}

	_, err = eng.Start("auto")
	if err == nil || err.Code != ipc.CodeAlreadyRunning {
		t.Fatalf("expected already_running, got %v", err)
	}

	st, err = eng.Stop()
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if st.State != engine.StateStopped || st.Protection {
		t.Fatalf("after stop: %+v", st)
	}

	_, err = eng.Stop()
	if err == nil || err.Code != ipc.CodeNotRunning {
		t.Fatalf("expected not_running, got %v", err)
	}
}

func TestStartUsesCatchAllNRPT(t *testing.T) {
	var got offdns.Config
	eng := newTestEngine(t).WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
		got = cfg
		return offdns.NewFakeSession(offdns.Info{
			ListenAddr: cfg.ListenAddr,
			LeakGuard:  cfg.ApplyLeakGuard,
			NRPT:       len(cfg.NRPTSuffixes) > 0,
		}), nil
	})
	if _, err := eng.Start("auto"); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _, _ = eng.Stop() })

	if got.ApplyLeakGuard {
		t.Fatal("leak-guard must stay off; catch-all NRPT is the steering path")
	}
	if len(got.NRPTSuffixes) != 1 || got.NRPTSuffixes[0] != offdns.NRPTCatchAll {
		t.Fatalf("NRPTSuffixes=%v want [%q]", got.NRPTSuffixes, offdns.NRPTCatchAll)
	}
	ns := offdns.NRPTNamespaces(got.NRPTSuffixes)
	if len(ns) != 1 || ns[0] != "." {
		t.Fatalf("NRPTNamespaces(%v)=%v want [.]", got.NRPTSuffixes, ns)
	}
	if got.OnQuery == nil {
		t.Fatal("expected OnQuery for package expand")
	}
	// Non-package hosts must not panic; expandCandidate returns before goroutine.
	got.OnQuery("youtube.com")
	got.OnQuery("1.2.3.4.in-addr.arpa")
}

func TestStartBindsDesyncAndSplitDefault(t *testing.T) {
	var desCfg desync.Config
	var tunCfg tunnel.Config
	eng := newTestEngine(t).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return capture.NewFakeSession(capture.Info{
				RoutesApplied: 1,
				Egress:        &capture.EgressInfo{Name: "Ethernet", IPv4: "192.168.0.10"},
			}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			desCfg = cfg
			return desync.NewFakeSession(desync.Info{
				SocksAddr: "127.0.0.1:18080", Up: true, LastProbe: desync.FailOK,
			}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
			tunCfg = cfg
			return tunnel.NewFakeSession(tunnel.Info{
				ProviderID: tunnel.ProviderDesync, Up: true, LastProbe: tunnel.FailOK,
			}), nil
		})
	if _, err := eng.Start("auto"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = eng.Stop() })
	if desCfg.ConnIP != "192.168.0.10" {
		t.Fatalf("ConnIP=%q want egress IPv4", desCfg.ConnIP)
	}
	got := strings.Join(tunCfg.RouteCIDRs, ",")
	if !strings.Contains(got, "0.0.0.0/1") || !strings.Contains(got, "128.0.0.0/1") {
		t.Fatalf("RouteCIDRs=%v want split-default", tunCfg.RouteCIDRs)
	}
}

func TestCrashCleanup(t *testing.T) {
	eng := newTestEngine(t)
	if _, err := eng.Start("auto"); err != nil {
		t.Fatal(err)
	}
	eng.CrashCleanup("test")
	st := eng.Status()
	if st.State != engine.StateStopped || st.Protection {
		t.Fatalf("after crash cleanup: %+v", st)
	}
}

func TestRepairStopsProtection(t *testing.T) {
	eng := newTestEngine(t).WithRepair(func() repair.Result {
		return repair.Result{Steps: []repair.Step{{Name: "policy", OK: true, Detail: "cleared"}}}
	})
	if _, err := eng.Start("auto"); err != nil {
		t.Fatal(err)
	}
	res, err := eng.Repair()
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	if res.Status == nil || res.Status.Protection || res.Status.State != engine.StateStopped {
		t.Fatalf("after repair: %+v", res.Status)
	}
	if len(res.Steps) != 1 || res.Steps[0].Name != "policy" || !res.Steps[0].OK {
		t.Fatalf("steps=%+v", res.Steps)
	}

	res, err = eng.Repair()
	if err != nil {
		t.Fatal(err)
	}
	if res.Status.Protection {
		t.Fatal("idempotent repair should stay stopped")
	}
}

func TestBadMode(t *testing.T) {
	eng := newTestEngine(t)
	_, err := eng.Start("manual")
	if err == nil || err.Code != ipc.CodeBadRequest {
		t.Fatalf("expected bad_request, got %v", err)
	}
}

func TestDesyncFailDegraded(t *testing.T) {
	t.Setenv("OFFVEIL_RULESET_SKIP_UPDATE", "1")
	t.Setenv("OFFVEIL_DESYNC_CACHE", t.TempDir())
	uniquePolicyCache(t)
	store, serr := desync.OpenStrategyStore("")
	if serr != nil {
		t.Fatal(serr)
	}
	reg := cleanup.NewRegistry()
	eng := engine.New(reg).
		WithStrategyStore(store).
		WithDesyncScan(func(ctx context.Context, cfg desync.ScanConfig) desync.ScanResult {
			return desync.ScanResult{OK: false, Reason: "exhausted", Tried: []desync.Tried{{StrategyID: "byedpi:windows-safe", Class: desync.FailReset}}}
		}).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return capture.NewFakeSession(capture.Info{RoutesApplied: 1}), nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			return offdns.NewFakeSession(offdns.Info{ListenAddr: "127.0.0.1:53"}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			if cfg.Sink != nil {
				cfg.Sink.OnDesyncFail(desync.FailSignal{
					Target:     "discord.com",
					Class:      desync.FailReset,
					StrategyID: "byedpi:windows-safe",
				})
			}
			return desync.NewFakeSession(desync.Info{
				SocksAddr:  "127.0.0.1:18080",
				StrategyID: "byedpi:windows-safe",
				LastProbe:  desync.FailReset,
			}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
			if cfg.Sink != nil {
				cfg.Sink.OnTunnelOK("discord.com", string(tunnel.ProviderWARP))
			}
			return tunnel.NewFakeSession(tunnel.Info{
				SocksAddr:  "127.0.0.1:18081",
				ProviderID: tunnel.ProviderWARP,
				Up:         true,
				LastProbe:  tunnel.FailOK,
			}), nil
		}).
		WithProbe(fakeDesyncProbe).
		WithNetInfo(fakeNet)

	st, err := eng.Start("auto")
	if err != nil {
		t.Fatal(err)
	}
	if st.State != engine.StateActive {
		t.Fatalf("state=%s want active (tunnel recovered)", st.State)
	}
	if st.OutboundHint != "desync" {
		t.Fatalf("hint=%q want desync (default HTTPS)", st.OutboundHint)
	}
	if st.Tunnel == nil {
		t.Fatal("expected tunnel info")
	}
	if len(st.Targets) == 0 || st.Targets[0].Path != "tunnel" {
		t.Fatalf("discord target=%+v want tunnel", st.Targets[0])
	}
	if st.Desync == nil {
		t.Fatal("ByeDPI must stay up; Discord tunnel is special-only")
	}
}

func TestDesyncSuccessStartsDataplane(t *testing.T) {
	eng := newTestEngine(t)
	st, err := eng.Start("auto")
	if err != nil {
		t.Fatal(err)
	}
	if st.OutboundHint != "desync" {
		t.Fatalf("hint=%q want desync", st.OutboundHint)
	}
	if st.Desync == nil {
		t.Fatal("expected ByeDPI to stay up")
	}
	if st.Tunnel == nil {
		t.Fatal("expected sing-box TUN dataplane")
	}
	ti, ok := st.Tunnel.(*tunnel.Info)
	if !ok || ti.ProviderID != tunnel.ProviderDesync {
		t.Fatalf("dataplane=%+v", st.Tunnel)
	}
}

func TestDesyncFailEscalatesWithoutScan(t *testing.T) {
	t.Setenv("OFFVEIL_RULESET_SKIP_UPDATE", "1")
	t.Setenv("OFFVEIL_DESYNC_CACHE", t.TempDir())
	uniquePolicyCache(t)
	store, serr := desync.OpenStrategyStore("")
	if serr != nil {
		t.Fatal(serr)
	}
	reg := cleanup.NewRegistry()
	scanCalls := 0
	eng := engine.New(reg).
		WithStrategyStore(store).
		WithDesyncScan(func(ctx context.Context, cfg desync.ScanConfig) desync.ScanResult {
			scanCalls++
			return desync.ScanResult{OK: true, Reason: "should-not-run"}
		}).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return capture.NewFakeSession(capture.Info{
				RoutesApplied: 1,
				RoutePrefixes: []string{"162.159.128.233/32"},
			}), nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			return offdns.NewFakeSession(offdns.Info{ListenAddr: "127.0.0.1:53"}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			if cfg.Sink != nil {
				cfg.Sink.OnDesyncFail(desync.FailSignal{
					Target: "discord.com", Class: desync.FailReset, StrategyID: "byedpi:windows-safe",
				})
			}
			return desync.NewFakeSession(desync.Info{
				SocksAddr: "127.0.0.1:18080", LastProbe: desync.FailReset,
			}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
			if cfg.AllowlistOutbound != "tunnel" {
				t.Fatalf("outbound=%q want tunnel", cfg.AllowlistOutbound)
			}
			if cfg.DesyncSOCKS == "" {
				t.Fatal("mixed dataplane needs ByeDPI SOCKS")
			}
			if !cfg.EnableTUN {
				t.Fatal("expected EnableTUN")
			}
			if cfg.Sink != nil {
				cfg.Sink.OnTunnelOK("discord.com", string(tunnel.ProviderWARP))
			}
			return tunnel.NewFakeSession(tunnel.Info{
				SocksAddr: "127.0.0.1:18081", ProviderID: tunnel.ProviderWARP,
				Up: true, LastProbe: tunnel.FailOK,
			}), nil
		}).
		WithProbe(fakeDesyncProbe).
		WithNetInfo(fakeNet)

	st, err := eng.Start("auto")
	if err != nil {
		t.Fatal(err)
	}
	if scanCalls != 0 {
		t.Fatalf("scan should not block start, calls=%d", scanCalls)
	}
	if st.OutboundHint != "desync" {
		t.Fatalf("hint=%q want desync (default HTTPS)", st.OutboundHint)
	}
	if st.Desync == nil {
		t.Fatal("ByeDPI must stay up after Discord-only tunnel escalate")
	}
}

func TestTunnelFailRetryHint(t *testing.T) {
	t.Setenv("OFFVEIL_RULESET_SKIP_UPDATE", "1")
	t.Setenv("OFFVEIL_DESYNC_CACHE", t.TempDir())
	uniquePolicyCache(t)
	store, _ := desync.OpenStrategyStore("")
	reg := cleanup.NewRegistry()
	eng := engine.New(reg).
		WithStrategyStore(store).
		WithDesyncScan(func(ctx context.Context, cfg desync.ScanConfig) desync.ScanResult {
			return desync.ScanResult{OK: false, Reason: "exhausted"}
		}).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return capture.NewFakeSession(capture.Info{RoutesApplied: 1}), nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			return offdns.NewFakeSession(offdns.Info{ListenAddr: "127.0.0.1:53"}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			if cfg.Sink != nil {
				cfg.Sink.OnDesyncFail(desync.FailSignal{
					Target: "discord.com", Class: desync.FailTimeout, StrategyID: "byedpi:windows-safe",
				})
			}
			return desync.NewFakeSession(desync.Info{LastProbe: desync.FailTimeout}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
			if cfg.Sink != nil {
				cfg.Sink.OnTunnelFail(tunnel.FailSignal{
					Target: "discord.com", Class: tunnel.FailAuth, ProviderID: string(tunnel.ProviderWARP), Detail: "register failed",
				})
			}
			return tunnel.NewFakeSession(tunnel.Info{
				ProviderID: tunnel.ProviderWARP,
				Up:         false,
				RetryHint:  true,
				LastProbe:  tunnel.FailAuth,
				FailDetail: "register failed",
			}), nil
		}).
		WithProbe(fakeDesyncProbe).
		WithNetInfo(fakeNet)

	st, err := eng.Start("auto")
	if err != nil {
		t.Fatal(err)
	}
	if st.State != engine.StateDegraded {
		t.Fatalf("state=%s want degraded", st.State)
	}
	if st.Summary != "Bozuldu" {
		t.Fatalf("summary=%q", st.Summary)
	}
	if len(st.Targets) == 0 || st.Targets[0].Outcome != "retry" {
		t.Fatalf("targets=%+v", st.Targets)
	}
}

func TestProbeDirectStillStartsDesync(t *testing.T) {
	uniquePolicyCache(t)
	reg := cleanup.NewRegistry()
	desyncStarted := false
	tunnelStarted := false
	eng := engine.New(reg).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return capture.NewFakeSession(capture.Info{RoutesApplied: 1}), nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			return offdns.NewFakeSession(offdns.Info{ListenAddr: "127.0.0.1:53"}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			desyncStarted = true
			return desync.NewFakeSession(desync.Info{Up: true}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
			tunnelStarted = true
			return tunnel.NewFakeSession(tunnel.Info{Up: true}), nil
		}).
		WithProbe(func(_ context.Context, _ *offdns.DoHClient, hosts []string) probe.Report {
			return probe.Report{Results: []probe.Result{{
				Target: hosts[0], Class: probe.ClassOpen, Path: "direct", OK: true,
			}}}
		}).
		WithNetInfo(fakeNet)

	st, err := eng.Start("auto")
	if err != nil {
		t.Fatal(err)
	}
	if !desyncStarted || !tunnelStarted {
		t.Fatalf("sidecars must start even when Discord is open (desync=%v tun=%v)", desyncStarted, tunnelStarted)
	}
	if st.OutboundHint != "desync" {
		t.Fatalf("hint=%q want desync", st.OutboundHint)
	}
	if st.Summary != "Açık" {
		t.Fatalf("summary=%q", st.Summary)
	}
	if path := ""; len(st.Targets) > 0 {
		for _, tg := range st.Targets {
			if tg.ID == "discord" {
				path = tg.Path
			}
		}
		if path != "direct" {
			t.Fatalf("discord path=%q want direct", path)
		}
	}
}

func TestTunnelEscalateDiscordOnly(t *testing.T) {
	t.Setenv("OFFVEIL_RULESET_SKIP_UPDATE", "1")
	t.Setenv("OFFVEIL_DESYNC_CACHE", t.TempDir())
	uniquePolicyCache(t)

	reg := cleanup.NewRegistry()
	store, err := desync.OpenStrategyStore("")
	if err != nil {
		t.Fatal(err)
	}
	desyncCalls := 0
	eng := engine.New(reg).
		WithStrategyStore(store).
		WithDesyncScan(func(ctx context.Context, cfg desync.ScanConfig) desync.ScanResult {
			return desync.ScanResult{OK: false, Reason: "test-skip"}
		}).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return capture.NewFakeSession(capture.Info{RoutesApplied: 1}), nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			return offdns.NewFakeSession(offdns.Info{ListenAddr: "127.0.0.1:53"}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			desyncCalls++
			return desync.NewFakeSession(desync.Info{
				SocksAddr: "127.0.0.1:18080", StrategyID: cfg.Strategy.ID,
				LastProbe: desync.FailTimeout, Up: true,
			}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
			return tunnel.NewFakeSession(tunnel.Info{
				ProviderID: tunnel.ProviderWARP, Up: true, LastProbe: tunnel.FailOK,
			}), nil
		}).
		WithProbe(func(_ context.Context, _ *offdns.DoHClient, hosts []string) probe.Report {
			var results []probe.Result
			for _, h := range hosts {
				results = append(results, probe.Result{
					Target: h, Class: probe.ClassTimeout, Path: "desync", OK: false,
				})
			}
			return probe.Report{Results: results, Chosen: "desync"}
		}).
		WithNetInfo(fakeNet)

	st, rpcErr := eng.Start("auto")
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if st.OutboundHint != "desync" {
		t.Fatalf("hint=%q want desync", st.OutboundHint)
	}
	var discord, imvu ipc.TargetStatus
	for _, tg := range st.Targets {
		switch tg.ID {
		case "discord":
			discord = tg
		case "imvu":
			imvu = tg
		}
	}
	if discord.Path != "tunnel" {
		t.Fatalf("discord=%+v want tunnel", discord)
	}
	if imvu.Path == "tunnel" {
		t.Fatalf("IMVU must not inherit Discord tunnel: %+v", imvu)
	}
	if _, err := eng.Stop(); err != nil {
		t.Fatal(err)
	}

	st2, rpcErr := eng.Start("auto")
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if st2.OutboundHint != "desync" {
		t.Fatalf("2nd hint=%q", st2.OutboundHint)
	}
	if desyncCalls != 2 {
		t.Fatalf("desyncCalls=%d want 2 (ASN cache must not skip default desync)", desyncCalls)
	}
}

func TestProbeIPDropStartsTunnel(t *testing.T) {
	uniquePolicyCache(t)
	reg := cleanup.NewRegistry()
	eng := engine.New(reg).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return capture.NewFakeSession(capture.Info{RoutesApplied: 1}), nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			return offdns.NewFakeSession(offdns.Info{ListenAddr: "127.0.0.1:53"}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			return desync.NewFakeSession(desync.Info{Up: true, LastProbe: desync.FailOK}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
			return tunnel.NewFakeSession(tunnel.Info{
				ProviderID: tunnel.ProviderWARP, Up: true, LastProbe: tunnel.FailOK,
			}), nil
		}).
		WithProbe(func(_ context.Context, _ *offdns.DoHClient, hosts []string) probe.Report {
			return probe.Report{Results: []probe.Result{{
				Target: hosts[0], Class: probe.ClassIPDrop, Path: "tunnel", OK: true,
			}}}
		}).
		WithNetInfo(fakeNet)

	st, err := eng.Start("auto")
	if err != nil {
		t.Fatal(err)
	}
	if st.OutboundHint != "desync" || st.Tunnel == nil {
		t.Fatalf("%+v", st)
	}
	if len(st.Targets) == 0 || st.Targets[0].Path != "tunnel" {
		t.Fatalf("discord want tunnel, got %+v", st.Targets)
	}
}

func TestTunnelFailoverUsesSecondProvider(t *testing.T) {
	uniquePolicyCache(t)
	reg := cleanup.NewRegistry()
	calls := 0
	eng := engine.New(reg).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return capture.NewFakeSession(capture.Info{RoutesApplied: 1}), nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			return offdns.NewFakeSession(offdns.Info{ListenAddr: "127.0.0.1:53"}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			return desync.NewFakeSession(desync.Info{Up: true, LastProbe: desync.FailOK}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
			calls++
			// Simulate tunnel.Start failover result: Reality after WARP failed.
			if cfg.Sink != nil {
				cfg.Sink.OnTunnelOK("discord.com", string(tunnel.ProviderReality))
			}
			return tunnel.NewFakeSession(tunnel.Info{
				ProviderID:     tunnel.ProviderReality,
				Up:             true,
				LastProbe:      tunnel.FailOK,
				FailoverFrom:   tunnel.ProviderWARP,
				ProvidersTried: []tunnel.ProviderID{tunnel.ProviderWARP, tunnel.ProviderReality},
			}), nil
		}).
		WithProbe(func(_ context.Context, _ *offdns.DoHClient, hosts []string) probe.Report {
			return probe.Report{Results: []probe.Result{{
				Target: hosts[0], Class: probe.ClassIPDrop, Path: "tunnel", OK: true,
			}}, Chosen: "tunnel"}
		}).
		WithNetInfo(fakeNet)

	st, err := eng.Start("auto")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
	if st.State != engine.StateActive {
		t.Fatalf("state=%s", st.State)
	}
	if st.OutboundHint != "desync" || st.Tunnel == nil {
		t.Fatalf("want desync default in outbound_hint, got summary=%q hint=%q", st.Summary, st.OutboundHint)
	}
	if st.Summary != "Açık" {
		t.Fatalf("summary=%q", st.Summary)
	}
}

func TestConnectionTest(t *testing.T) {
	eng := newTestEngine(t)
	_, err := eng.Test(nil)
	if err == nil || err.Code != ipc.CodeNotRunning {
		t.Fatalf("expected not_running, got %v", err)
	}
	if _, err := eng.Start("auto"); err != nil {
		t.Fatal(err)
	}
	stBefore := eng.Status()
	rep, err := eng.Test([]string{"discord.com"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ASN != "9121" || len(rep.Results) != 1 {
		t.Fatalf("%+v", rep)
	}
	stAfter := eng.Status()
	if stAfter.Summary != stBefore.Summary {
		t.Fatalf("test must not rewrite summary: before=%q after=%q", stBefore.Summary, stAfter.Summary)
	}
	if stAfter.OutboundHint != stBefore.OutboundHint {
		t.Fatalf("test must not demote hint: before=%q after=%q", stBefore.OutboundHint, stAfter.OutboundHint)
	}
	if len(stAfter.Targets) > 0 && stAfter.Targets[0].Path != stBefore.Targets[0].Path {
		t.Fatalf("test must not rewrite targets: before=%+v after=%+v", stBefore.Targets[0], stAfter.Targets[0])
	}
}

func TestConnectionTestDoesNotDemoteTunnel(t *testing.T) {
	uniquePolicyCache(t)
	t.Setenv("OFFVEIL_RULESET_SKIP_UPDATE", "1")
	t.Setenv("OFFVEIL_DESYNC_CACHE", t.TempDir())
	reg := cleanup.NewRegistry()
	store, _ := desync.OpenStrategyStore("")
	eng := engine.New(reg).
		WithStrategyStore(store).
		WithDesyncScan(func(ctx context.Context, cfg desync.ScanConfig) desync.ScanResult {
			return desync.ScanResult{OK: false, Reason: "skip"}
		}).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return capture.NewFakeSession(capture.Info{RoutesApplied: 1}), nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			return offdns.NewFakeSession(offdns.Info{ListenAddr: "127.0.0.1:53"}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			return desync.NewFakeSession(desync.Info{LastProbe: desync.FailTimeout, Up: true}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
			return tunnel.NewFakeSession(tunnel.Info{
				ProviderID: tunnel.ProviderWARP, Up: true, LastProbe: tunnel.FailOK,
			}), nil
		}).
		WithProbe(func(_ context.Context, _ *offdns.DoHClient, hosts []string) probe.Report {
			var results []probe.Result
			for _, h := range hosts {
				results = append(results, probe.Result{
					Target: h, Class: probe.ClassTimeout, Path: "desync", OK: false,
				})
			}
			return probe.Report{Results: results, Chosen: "desync"}
		}).
		WithNetInfo(fakeNet)

	if _, err := eng.Start("auto"); err != nil {
		t.Fatal(err)
	}
	st := eng.Status()
	if st.OutboundHint != "desync" {
		t.Fatalf("hint=%q want desync", st.OutboundHint)
	}
	if len(st.Targets) == 0 || st.Targets[0].Path != "tunnel" {
		t.Fatalf("discord path=%+v want tunnel", st.Targets)
	}
	// Probe would say desync; must not rewrite Discord target off tunnel.
	eng.WithProbe(func(_ context.Context, _ *offdns.DoHClient, hosts []string) probe.Report {
		return probe.Report{Results: []probe.Result{{
			Target: hosts[0], Class: probe.ClassDPIReset, Path: "desync", OK: true,
		}}, Chosen: "desync"}
	})
	if _, err := eng.Test([]string{"discord.com"}); err != nil {
		t.Fatal(err)
	}
	st2 := eng.Status()
	if st2.OutboundHint != "desync" {
		t.Fatalf("hint=%q", st2.OutboundHint)
	}
	if len(st2.Targets) == 0 || st2.Targets[0].Path != "tunnel" {
		t.Fatalf("discord demoted to %+v", st2.Targets)
	}
	if st2.Summary != "Açık" {
		t.Fatalf("summary=%q", st2.Summary)
	}
}
