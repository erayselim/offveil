package dns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestPlainFallbackCoalescesWithIndependentCancellation(t *testing.T) {
	c := NewDoHClient(nil)
	defer c.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c.plainExchange = func(ctx context.Context, q *mdns.Msg) (*mdns.Msg, string, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-release:
			return dnsAnswer(q, "203.0.113.10", 60), "plain-test", nil
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, _, err := c.exchangePlain(ctx, dnsQuestion("fallback.test", 1)); first <- err }()
	<-entered
	second := make(chan *mdns.Msg, 1)
	go func() {
		resp, _, _ := c.exchangePlain(context.Background(), dnsQuestion("fallback.test", 2))
		second <- resp
	}()
	deadline := time.Now().Add(time.Second)
	joined := false
	for time.Now().Before(deadline) {
		c.queriesMu.Lock()
		for _, f := range c.flights {
			joined = f.waiters == 2
		}
		c.queriesMu.Unlock()
		if joined {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("first waiter cancellation: %v", err)
	}
	close(release)
	response := <-second
	if !joined || calls.Load() != 1 || response == nil || response.Id != 2 {
		t.Fatalf("shared fallback failed: joined=%t calls=%d response=%v", joined, calls.Load(), response)
	}
	response.Answer = nil
	// A later query must retry the upstream instead of caching plain DNS.
	third, _, err := c.exchangePlain(context.Background(), dnsQuestion("fallback.test", 3))
	if err != nil || calls.Load() != 2 || third.Id != 3 || len(third.Answer) != 1 || len(c.cache) != 0 {
		t.Fatalf("plain answer was cached or aliased: %v %v", third, err)
	}
}

func TestPlainFallbackResetDetachesPreviousFlight(t *testing.T) {
	c := NewDoHClient(nil)
	defer c.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c.plainExchange = func(ctx context.Context, q *mdns.Msg) (*mdns.Msg, string, error) {
		if calls.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, "", ctx.Err()
			}
		}
		return dnsAnswer(q, "203.0.113.10", 60), "plain-test", nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = c.exchangePlain(context.Background(), dnsQuestion("fallback.test", 1))
	}()
	<-entered
	c.ResetCache()
	_, _, err := c.exchangePlain(context.Background(), dnsQuestion("fallback.test", 2))
	close(release)
	<-done
	if err != nil || calls.Load() != 2 {
		t.Fatalf("new network joined old plain DNS flight: calls=%d err=%v", calls.Load(), err)
	}
}
