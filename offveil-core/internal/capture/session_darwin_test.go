//go:build darwin

package capture_test

import (
	"os"
	"strings"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
)

func TestStartRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root")
	}
	_, err := capture.Start(capture.DefaultConfig())
	if err == nil || !strings.Contains(err.Error(), "privilege") {
		t.Fatalf("want privilege, got %v", err)
	}
}

func TestCloseOrphanAdapterNoop(t *testing.T) {
	if err := capture.CloseOrphanAdapter(); err != nil {
		t.Fatal(err)
	}
}

func TestTakeSnapshotNonRoot(t *testing.T) {
	snap, err := capture.TakeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap == nil || len(snap.Adapters) == 0 {
		t.Fatal("expected adapters")
	}
}
