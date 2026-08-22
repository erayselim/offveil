package netwatch_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/netwatch"
)

func TestStartFiresOnFingerprintChange(t *testing.T) {
	prevDebounce := netwatch.Debounce
	netwatch.Debounce = 40 * time.Millisecond
	defer func() { netwatch.Debounce = prevDebounce }()

	var seq atomic.Int32
	fp := func() string {
		n := seq.Load()
		if n == 0 {
			return "aaaaaaaaaaaaaaaa"
		}
		return "bbbbbbbbbbbbbbbb"
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan struct{}, 1)
	netwatch.Start(ctx, 30*time.Millisecond, fp, func(prev, next string) {
		if prev == "aaaaaaaaaaaaaaaa" && next == "bbbbbbbbbbbbbbbb" {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	})

	time.Sleep(50 * time.Millisecond)
	seq.Store(1)

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("expected onChange after fingerprint flip")
	}
}

func TestStartIgnoresOffline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fired := atomic.Bool{}
	netwatch.Start(ctx, 30*time.Millisecond, func() string { return "offline" }, func(_, _ string) {
		fired.Store(true)
	})
	time.Sleep(200 * time.Millisecond)
	if fired.Load() {
		t.Fatal("offline fingerprint must not fire onChange")
	}
}
