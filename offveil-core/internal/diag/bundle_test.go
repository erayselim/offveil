package diag_test

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
)

func TestWriteZipOmitsPublicIPAndScrubs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFVEIL_DIAG_DIR", dir)

	meta, err := diag.WriteZip(diag.Input{
		Network: diag.NetworkInfo{
			ASN:         "9121",
			ISPHint:     "Turk Telekom",
			Fingerprint: "deadbeefdeadbeef",
		},
		Cascade: diag.CascadeInfo{
			State:        "active",
			Protection:   true,
			Summary:      "Aktif · Discord · desync",
			OutboundHint: "desync",
			Health:       "ok",
			Targets: []diag.TargetRow{
				{ID: "discord", Label: "Discord", Outcome: "ok", Path: "desync"},
			},
			LastError: `tun failed open C:\Users\eray\AppData\Local\Temp\x err 203.82.1.1`,
		},
		Probe: &diag.ProbeInfo{
			ASN: "9121",
			Results: []diag.ProbeRow{
				{Target: "discord.com", Class: "dpi_reset", Path: "desync", OK: true},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Path == "" || meta.SHA256 == "" {
		t.Fatalf("meta: %+v", meta)
	}
	if _, err := os.Stat(meta.Path); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.OpenReader(meta.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	var raw []byte
	for _, f := range zr.File {
		if f.Name == "diagnostics.json" {
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
	}
	if len(raw) == 0 {
		t.Fatal("diagnostics.json missing")
	}
	body := string(raw)
	if strings.Contains(body, "eray") {
		t.Fatal("username leaked in bundle")
	}
	if strings.Contains(body, "203.82.1.1") {
		t.Fatal("public/literal IP leaked in bundle")
	}
	if !strings.Contains(body, `"asn": "9121"`) {
		t.Fatal("expected ASN in bundle")
	}
	if strings.Contains(strings.ToLower(body), "public_ip") || strings.Contains(body, "PublicIP") {
		t.Fatal("must not include public IP field")
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	cascade, _ := m["cascade"].(map[string]any)
	if cascade == nil {
		t.Fatal("cascade missing")
	}
	if ec, _ := cascade["error_class"].(string); ec == "" {
		t.Fatal("expected error_class")
	}
}

func TestScrub(t *testing.T) {
	got := diag.Scrub(`fail C:\Users\eray\secret 8.8.8.8`)
	if strings.Contains(got, "eray") || strings.Contains(got, "8.8.8.8") {
		t.Fatalf("scrub failed: %q", got)
	}
}

func TestScrubTreeSidecarPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFVEIL_DIAG_DIR", dir)

	meta, err := diag.WriteZip(diag.Input{
		Network: diag.NetworkInfo{ASN: "9121", Fingerprint: "fp"},
		Cascade: diag.CascadeInfo{
			State: "active", Protection: true, Summary: "Açık", OutboundHint: "tunnel", Health: "ok",
		},
		Sidecars: map[string]any{
			"capture": map[string]any{
				"dll_path": `C:\Users\eray\offveil\offveil-core\wintun.dll`,
			},
			"tunnel": map[string]any{
				"binary_path": `C:\Users\eray\offveil\offveil-core\third_party\sing-box\sing-box.exe`,
				"config_path": `C:\Users\eray\offveil\offveil-core\data\sing-box-tunnel.json`,
			},
		},
	})
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
	if strings.Contains(body, "eray") {
		t.Fatalf("username leaked in sidecar paths: %s", body)
	}
	if !strings.Contains(body, `C:\\Users\\_`) && !strings.Contains(body, `C:\Users\_`) {
		t.Fatalf("expected scrubbed path placeholder, got: %s", body)
	}
}
