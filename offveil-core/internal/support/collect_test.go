package support

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
)

func TestOfflineBundleWithoutService(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	in := Collect(ctx, func(ctx context.Context, _ string) (json.RawMessage, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if in.System["collection_mode"] != "offline" || in.Cascade.State != "unavailable" {
		t.Fatalf("%+v", in)
	}
	if in.System["protection_state"] != "unknown" {
		t.Fatal("offline state was treated as measured off")
	}
	output := filepath.Join(t.TempDir(), "support.zip")
	meta, err := Write(in, output)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Path != output {
		t.Fatalf("output=%s", meta.Path)
	}
	zr, err := zip.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if len(zr.File) != 3 {
		t.Fatalf("files=%d", len(zr.File))
	}
	for _, file := range zr.File {
		if file.Name != "diagnostics.json" {
			continue
		}
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"collection_mode": "offline"`) {
			t.Fatal(string(body))
		}
	}
}

func TestLiveBundleAndExternalPathRejected(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	meta, err := diag.WriteZip(diag.Input{Cascade: diag.CascadeInfo{State: "active", Protection: true}, System: map[string]any{"protection_state": "off"}, Notes: []string{"Protection is currently off; retained active snapshot."}})
	if err != nil {
		t.Fatal(err)
	}
	rpc := func(context.Context, string) (json.RawMessage, error) {
		raw, err := json.Marshal(meta)
		return raw, err
	}
	in := Collect(context.Background(), rpc)
	if in.Cascade.State != "active" || in.System["collection_mode"] != "live" || in.System["protection_state"] != "off" {
		t.Fatalf("%+v", in)
	}
	// An older daemon returns only a path; it must stay inside Dir().
	meta.Report = nil
	meta.Path = filepath.Join(t.TempDir(), "unrelated.txt")
	if err := os.WriteFile(meta.Path, []byte("private file"), 0o600); err != nil {
		t.Fatal(err)
	}
	in = Collect(context.Background(), rpc)
	if in.System["collection_mode"] != "offline" {
		t.Fatal("accepted path outside diagnostics directory")
	}
}

func TestInlineReportNeedsNoAccessToDaemonDirectory(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	meta, err := diag.WriteZip(diag.Input{Cascade: diag.CascadeInfo{State: "active", Protection: true, Summary: "Açık"},
		System:   map[string]any{"protection_state": "on"},
		Failures: []diag.Failure{{Component: "engine", Event: "layer_started"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Report) == 0 {
		t.Fatal("daemon reply lacks the inline report")
	}
	meta.Path = filepath.Join(t.TempDir(), "root-only", "missing.zip")
	in := Collect(context.Background(), func(context.Context, string) (json.RawMessage, error) { return json.Marshal(meta) })
	if in.System["collection_mode"] != "live" || in.System["protection_state"] != "on" || in.Cascade.Summary != "Açık" {
		t.Fatalf("inline report ignored: %+v", in.System)
	}
	if len(in.Failures) != 1 || in.Failures[0].Event != "layer_started" {
		t.Fatalf("daemon journal lost: %+v", in.Failures)
	}
}

func TestPermissionDeniedFileIsUnknownNotMissing(t *testing.T) {
	if os.Geteuid() == 0 || os.PathSeparator == '\\' {
		t.Skip("needs an unprivileged POSIX user")
	}
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ciadpi"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0o000)
	defer os.Chmod(dir, 0o700)
	if fact := fileFact(filepath.Join(dir, "ciadpi")); fact["exists"] != "unknown" {
		t.Fatalf("fact=%+v", fact)
	}
}
