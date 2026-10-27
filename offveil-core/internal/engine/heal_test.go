package engine_test

import (
	"archive/zip"
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/engine"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func TestDiagnosticsBundle(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFVEIL_DIAG_DIR", dir)
	t.Setenv("OFFVEIL_POLICY_CACHE", t.TempDir())
	eng := newTestEngine(t)
	if _, err := eng.Start("auto"); err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()

	meta, err := eng.Diagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if meta.Path == "" || meta.SHA256 == "" {
		t.Fatalf("%+v", meta)
	}
	st := eng.Status()
	if st.Heal == nil {
		t.Fatal("expected heal status while watching")
	}
}

func TestDiagnosticsKeepsLastSessionAfterStop(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFVEIL_DIAG_DIR", dir)
	t.Setenv("OFFVEIL_POLICY_CACHE", t.TempDir())
	eng := newTestEngine(t)
	if _, err := eng.Start("auto"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Stop(); err != nil {
		t.Fatal(err)
	}
	meta, err := eng.Diagnostics()
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(meta.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var raw []byte
	for _, f := range zr.File {
		if f.Name != "diagnostics.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err = io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	body := string(raw)
	if !strings.Contains(body, `"outbound_hint"`) {
		t.Fatal("expected frozen cascade in stopped diagnostics")
	}
	if !strings.Contains(body, "last active session") {
		t.Fatal("expected note about last active session")
	}
	// Must not be the empty stopped-only package.
	if strings.Contains(body, `"sidecars": {}`) && !strings.Contains(body, `"capture"`) {
		t.Fatal("expected frozen sidecars after stop")
	}
}

func TestSelfHealOnFingerprintChange(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	eng := newTestEngine(t)

	var fp atomic.Value
	fp.Store("fp-aaaa")
	eng.WithNetInfo(func(ctx context.Context) netinfo.Info {
		return netinfo.Info{
			ASN:         "64512",
			ISPHint:     "Fixture network",
			Fingerprint: fp.Load().(string),
		}
	})

	if _, err := eng.Start("auto"); err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()

	fp.Store("fp-bbbb")
	eng.SelfHeal("network_change")

	st := eng.Status()
	if !st.Protection {
		t.Fatal("expected protection after heal")
	}
	heal, ok := st.Heal.(*engine.HealInfo)
	if !ok || heal.Count != 1 || heal.LastReason != "network_change" || !heal.Watching {
		t.Fatalf("heal bookkeeping: %+v", st.Heal)
	}
	requireNetworkTargets(t, st, "desync", "direct")
}

func TestSameInterfaceNetworkChangeKeepsGateway(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	var fp atomic.Value
	fp.Store("fp-aaaa")
	gateways, helpers := 0, 0
	var connIPs []string
	eng := newTestEngine(t).
		WithNetInfo(func(context.Context) netinfo.Info { return netinfo.Info{ASN: "64512", Fingerprint: fp.Load().(string)} }).
		WithTunnelStart(func(tunnel.Config) (tunnel.Session, error) { gateways++; return gatewaySession(), nil }).
		WithDesyncStart(func(cfg desync.Config) (desync.Session, error) {
			helpers++
			connIPs = append(connIPs, cfg.ConnIP)
			return desync.NewFakeSession(desync.Info{}), nil
		}).
		WithSnapshot(func() (*capture.Snapshot, error) {
			return &capture.Snapshot{Egress: &capture.EgressInfo{Name: "Ethernet", IPv4: "192.0.2.77"}}, nil
		})
	if _, err := eng.Start("auto"); err != nil {
		t.Fatal(err)
	}
	fp.Store("fp-bbbb")
	eng.SelfHeal("network_change")
	st := eng.Status()
	if gateways != 1 || helpers != 2 || connIPs[1] != "192.0.2.77" || !st.Protection || st.Transition != "" {
		t.Fatalf("soft rebind: gateways=%d helpers=%d ips=%v status=%+v", gateways, helpers, connIPs, st)
	}
	if heal := st.Heal.(*engine.HealInfo); heal.Count != 1 {
		t.Fatalf("heal count: %+v", heal)
	}
}
