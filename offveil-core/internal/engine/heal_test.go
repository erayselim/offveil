package engine_test

import (
	"archive/zip"
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/engine"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
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
			ASN:         "9121",
			ISPHint:     "TT",
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
	// Allow heal bookkeeping to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st = eng.Status()
		if h, ok := st.Heal.(map[string]any); ok && h != nil {
			break
		}
		// HealInfo is a struct encoded as JSON object via status - check typed path.
		if st.Heal != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.Heal == nil {
		t.Fatal("expected heal info after SelfHeal")
	}
}

// compile-time note: engine.StateActive used elsewhere
var _ = engine.StateActive
