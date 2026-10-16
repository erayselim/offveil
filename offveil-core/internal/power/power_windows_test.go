//go:build windows

package power

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestResumeSubscriptionsDoNotReuseOldContext(t *testing.T) {
	var oldCalls atomic.Int32
	old := subscribeResume(func() { oldCalls.Add(1) })
	unsubscribeResume(old)
	called := make(chan struct{}, 1)
	current := subscribeResume(func() { called <- struct{}{} })
	defer unsubscribeResume(current)
	if old == current || resumeCallback == 0 {
		t.Fatal("callback subscription context was reused")
	}
	dispatchResume(old, pbtAPMResumeAutomatic, 0)
	dispatchResume(current, 0, 0)
	dispatchResume(current, pbtAPMResumeAutomatic, 0)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("current power subscription did not receive resume")
	}
	if oldCalls.Load() != 0 {
		t.Fatal("closed subscription received a late event")
	}
	// Repeated sessions only allocate IDs; no new Go callback is compiled.
	for range 2048 {
		id := subscribeResume(func() {})
		unsubscribeResume(id)
	}
}
