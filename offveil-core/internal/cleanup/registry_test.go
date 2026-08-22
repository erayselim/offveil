package cleanup_test

import (
	"sync/atomic"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/cleanup"
)

func TestRegistryLIFO(t *testing.T) {
	reg := cleanup.NewRegistry()
	var order []int
	reg.Register("a", func() error { order = append(order, 1); return nil })
	reg.Register("b", func() error { order = append(order, 2); return nil })
	reg.Run("test")
	if len(order) != 2 || order[0] != 2 || order[1] != 1 {
		t.Fatalf("order=%v want LIFO [2 1]", order)
	}
}

func TestRegistryBestEffort(t *testing.T) {
	reg := cleanup.NewRegistry()
	var ran atomic.Bool
	reg.Register("fail", func() error { return assertErr{} })
	reg.Register("ok", func() error { ran.Store(true); return nil })
	reg.Run("test")
	if !ran.Load() {
		t.Fatal("expected later hook to run despite earlier error (LIFO: ok runs first)")
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "boom" }
