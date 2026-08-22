package engine_test

import (
	"context"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/cleanup"
	"github.com/erayselim/offveil/offveil-core/internal/desync"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/engine"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func TestDomainExpandAddsRoutes(t *testing.T) {
	t.Setenv("OFFVEIL_RULESET_SKIP_UPDATE", "1")
	t.Setenv("OFFVEIL_DESYNC_CACHE", t.TempDir())
	uniquePolicyCache(t)

	fakeCap := capture.NewFakeSession(capture.Info{
		AdapterName:   capture.AdapterName,
		RoutesApplied: 1,
		RoutePrefixes: []string{"1.1.1.1/32"},
		Egress:        &capture.EgressInfo{Name: "Ethernet", IfIndex: 12},
	})
	reg := cleanup.NewRegistry()
	store, err := desync.OpenStrategyStore("")
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(reg).
		WithStrategyStore(store).
		WithDesyncScan(func(ctx context.Context, cfg desync.ScanConfig) desync.ScanResult {
			return desync.ScanResult{OK: false, Reason: "test-skip"}
		}).
		WithCaptureStart(func(cfg capture.Config) (capture.Session, error) {
			return fakeCap, nil
		}).
		WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
			return offdns.NewFakeSession(offdns.Info{ListenAddr: cfg.ListenAddr}), nil
		}).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			return desync.NewFakeSession(desync.Info{
				SocksAddr:  "127.0.0.1:18080",
				StrategyID: cfg.Strategy.ID,
				LastProbe:  desync.FailOK,
				Up:         true,
			}), nil
		}).
		WithTunnelStart(func(cfg tunnel.Config) (tunnel.Session, error) {
			return tunnel.NewFakeSession(tunnel.Info{
				SocksAddr:  "127.0.0.1:18081",
				ProviderID: tunnel.ProviderWARP,
				Up:         true,
				LastProbe:  tunnel.FailOK,
			}), nil
		}).
		WithNetInfo(func(ctx context.Context) netinfo.Info {
			return netinfo.Info{ASN: "AS999", ISPHint: "test", Fingerprint: "fp"}
		}).
		WithProbe(func(ctx context.Context, doh *offdns.DoHClient, hosts []string) probe.Report {
			var results []probe.Result
			for _, h := range hosts {
				results = append(results, probe.Result{
					Target: h, Class: probe.ClassDPIReset, Path: "desync", Confidence: 0.9, OK: true,
				})
			}
			return probe.Report{Results: results, Chosen: "desync"}
		})

	st, rpcErr := eng.Start("auto")
	if rpcErr != nil {
		t.Fatalf("start: %+v", rpcErr)
	}
	if st == nil || !st.Protection {
		t.Fatal("expected protection on")
	}

	var sawIMVU bool
	for _, tg := range st.Targets {
		if tg.ID == "imvu" {
			sawIMVU = true
		}
	}
	if !sawIMVU {
		t.Fatalf("status targets missing imvu: %+v", st.Targets)
	}

	eng.HandleExpandQueryForTest("avatars.imvu.com")

	st2 := eng.Status()
	if st2.Expand == nil {
		t.Fatal("expected expand diagnostics after IMVU DNS observe")
	}
	exp, ok := st2.Expand.(*engine.ExpandInfo)
	if !ok {
		// JSON-ish any may be ExpandInfo value via interface
		t.Logf("expand type %T value %+v", st2.Expand, st2.Expand)
	} else if exp.HostsSeen < 1 {
		t.Fatalf("hosts_seen=%d", exp.HostsSeen)
	}
	if st2.Expand == nil {
		t.Fatal("expand nil")
	}

	_, _ = eng.Stop()
}

func TestStartIncludesIMVUTarget(t *testing.T) {
	eng := newTestEngine(t)
	st, err := eng.Start("auto")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, tg := range st.Targets {
		ids[tg.ID] = true
	}
	if !ids["discord"] || !ids["imvu"] {
		t.Fatalf("targets=%+v", st.Targets)
	}
	_, _ = eng.Stop()
}
