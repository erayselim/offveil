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
	meta, err := diag.WriteZip(diag.Input{Cascade: diag.CascadeInfo{State: "starting"}, Notes: []string{"startup_stage=tunnel"}})
	if err != nil {
		t.Fatal(err)
	}
	rpc := func(context.Context, string) (json.RawMessage, error) {
		raw, err := json.Marshal(meta)
		return raw, err
	}
	in := Collect(context.Background(), rpc)
	if in.Cascade.State != "starting" || in.System["collection_mode"] != "live" {
		t.Fatalf("%+v", in)
	}
	meta.Path = filepath.Join(t.TempDir(), "unrelated.txt")
	if err := os.WriteFile(meta.Path, []byte("private file"), 0o600); err != nil {
		t.Fatal(err)
	}
	in = Collect(context.Background(), rpc)
	if in.System["collection_mode"] != "offline" {
		t.Fatal("accepted path outside diagnostics directory")
	}
}
