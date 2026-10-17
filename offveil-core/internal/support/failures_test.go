package support

import (
	"context"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/proc"
)

func TestOfflineSupportRetainsPreviousDaemonFailure(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	if err := diag.RecordFailure(diag.Failure{Component: "desync", Event: "unavailable", Exit: &proc.ExitInfo{Code: 7, StderrClass: "file_limit"}}); err != nil {
		t.Fatal(err)
	}
	in := Collect(context.Background(), nil)
	if len(in.Failures) != 1 || in.Failures[0].Exit.Code != 7 || in.Failures[0].Exit.StderrClass != "file_limit" {
		t.Fatalf("previous daemon failure missing: %+v", in.Failures)
	}
}
