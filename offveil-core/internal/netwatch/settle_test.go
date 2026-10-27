package netwatch

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestChangingCandidateStillReportsFinalStableNetwork(t *testing.T) {
	previousDebounce := Debounce
	Debounce = 10 * time.Millisecond
	defer func() { Debounce = previousDebounce }()
	var samples atomic.Int32
	fingerprint := func() string {
		switch samples.Add(1) {
		case 1:
			return "network-a"
		case 2:
			return "network-b"
		default:
			return "network-c"
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done, changed := make(chan struct{}), make(chan [2]string, 1)
	go func() {
		defer close(done)
		run(ctx, 10*time.Millisecond, fingerprint, func(prev, next string) {
			changed <- [2]string{prev, next}
		})
	}()
	defer func() { cancel(); <-done }()
	select {
	case pair := <-changed:
		if pair != [2]string{"network-a", "network-c"} {
			t.Fatalf("stable change was not measured from the last reported network: %v", pair)
		}
	case <-time.After(5 * time.Second): // generous under a loaded full-suite run
		t.Fatal("debounce silently adopted an unreported network change")
	}
}
