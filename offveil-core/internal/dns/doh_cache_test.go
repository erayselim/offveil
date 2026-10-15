package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

type dohTransportFunc func(*http.Request) (*http.Response, error)

func (fn dohTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func testDoHClient(t *testing.T, answer func(*http.Request, *mdns.Msg) (*mdns.Msg, error)) *DoHClient {
	t.Helper()
	c := NewDoHClient(DefaultPoisonSet())
	c.endpoints = []string{"https://primary.test/dns-query"}
	c.client = &http.Client{Transport: dohTransportFunc(func(r *http.Request) (*http.Response, error) {
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		q := new(mdns.Msg)
		if err := q.Unpack(wire); err != nil {
			return nil, err
		}
		response, err := answer(r, q)
		if err != nil {
			return nil, err
		}
		wire, err = response.Pack()
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(wire))}, err
	})}
	t.Cleanup(c.Close)
	return c
}

func dnsQuestion(name string, id uint16) *mdns.Msg {
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	q.Id = id
	return q
}

func dnsAnswer(q *mdns.Msg, ip string, ttl uint32) *mdns.Msg {
	r := new(mdns.Msg)
	r.SetReply(q)
	rr, err := mdns.NewRR(fmt.Sprintf("%s %d IN A %s", q.Question[0].Name, ttl, ip))
	if err != nil {
		panic(err)
	}
	r.Answer = []mdns.RR{rr}
	return r
}

func TestDoHCacheCopiesIDsAgesTTLAndExpires(t *testing.T) {
	var calls atomic.Int32
	c := testDoHClient(t, func(_ *http.Request, q *mdns.Msg) (*mdns.Msg, error) {
		calls.Add(1)
		return dnsAnswer(q, "203.0.113.9", 30), nil
	})
	q := dnsQuestion("example.com", 11)
	first, _, err := c.Exchange(context.Background(), q)
	if err != nil || first.Id != 11 {
		t.Fatalf("first=%v err=%v", first, err)
	}
	first.Answer[0].Header().Ttl = 0
	c.queriesMu.Lock()
	for key, entry := range c.cache {
		entry.stored = time.Now().Add(-3 * time.Second)
		c.cache[key] = entry
	}
	c.queriesMu.Unlock()
	q.Id = 22
	second, _, err := c.Exchange(context.Background(), q)
	if err != nil || second.Id != 22 || second.Answer[0].Header().Ttl != 27 || calls.Load() != 1 {
		t.Fatalf("second=%v calls=%d err=%v", second, calls.Load(), err)
	}
	c.queriesMu.Lock()
	for key, entry := range c.cache {
		entry.expires = time.Now().Add(-time.Second)
		c.cache[key] = entry
	}
	c.queriesMu.Unlock()
	if _, _, err := c.Exchange(context.Background(), q); err != nil || calls.Load() != 2 {
		t.Fatalf("expired entry reused: calls=%d err=%v", calls.Load(), err)
	}
}

func TestDoHCacheSeparatesDNSFlagsAndEDNS(t *testing.T) {
	var calls atomic.Int32
	c := testDoHClient(t, func(_ *http.Request, q *mdns.Msg) (*mdns.Msg, error) {
		calls.Add(1)
		return dnsAnswer(q, "203.0.113.9", 30), nil
	})
	q := dnsQuestion("example.com", 1)
	for i := 0; i < 3; i++ {
		if i == 1 {
			q.CheckingDisabled = true
		}
		if i == 2 {
			q.SetEdns0(1232, true)
		}
		if _, _, err := c.Exchange(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("flags or EDNS questions merged: calls=%d", calls.Load())
	}
}

func waitDoHWaiters(t *testing.T, c *DoHClient, count int) *dohFlight {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.queriesMu.Lock()
		for _, flight := range c.flights {
			if flight.waiters == count {
				c.queriesMu.Unlock()
				return flight
			}
		}
		c.queriesMu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("did not observe %d DNS waiters", count)
	return nil
}

func TestDoHCoalescesButCancellationIsIndependent(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	c := testDoHClient(t, func(r *http.Request, q *mdns.Msg) (*mdns.Msg, error) {
		calls.Add(1)
		select {
		case <-release:
			return dnsAnswer(q, "203.0.113.9", 30), nil
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { _, _, err := c.Exchange(ctx, dnsQuestion("example.com", 1)); first <- err }()
	waitDoHWaiters(t, c, 1)
	second := make(chan error, 1)
	go func() {
		r, _, err := c.Exchange(context.Background(), dnsQuestion("example.com", 2))
		if err == nil && r.Id != 2 {
			err = fmt.Errorf("shared response has wrong ID %d", r.Id)
		}
		second <- err
	}()
	waitDoHWaiters(t, c, 2)
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("first caller: %v", err)
	}
	close(release)
	if err := <-second; err != nil || calls.Load() != 1 {
		t.Fatalf("second caller: calls=%d err=%v", calls.Load(), err)
	}
}

func TestDoHLastCancellationStopsWorkWithoutOpeningCircuit(t *testing.T) {
	c := testDoHClient(t, func(r *http.Request, _ *mdns.Msg) (*mdns.Msg, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, _, err := c.Exchange(ctx, dnsQuestion("example.com", 1)); result <- err }()
	flight := waitDoHWaiters(t, c, 1)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	select {
	case <-flight.done:
	case <-time.After(time.Second):
		t.Fatal("abandoned upstream work was not canceled")
	}
	if c.failStreak != 0 || len(c.cache) != 0 {
		t.Fatalf("cancellation was cached or counted as network failure: streak=%d cache=%d", c.failStreak, len(c.cache))
	}
}

func TestDoHDoesNotCacheUnsafeOrNegativeAnswers(t *testing.T) {
	for _, kind := range []string{"zero_ttl", "poison", "nxdomain", "servfail", "empty", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			c := testDoHClient(t, func(_ *http.Request, q *mdns.Msg) (*mdns.Msg, error) {
				calls.Add(1)
				r := dnsAnswer(q, "203.0.113.9", 30)
				switch kind {
				case "zero_ttl":
					r.Answer[0].Header().Ttl = 0
				case "poison":
					r = dnsAnswer(q, "195.175.254.2", 30)
				case "nxdomain":
					r.Rcode = mdns.RcodeNameError
				case "servfail":
					r.Rcode = mdns.RcodeServerFailure
				case "empty":
					r.Answer = nil
				case "truncated":
					r.Truncated = true
				}
				return r, nil
			})
			for i := 0; i < 2; i++ {
				if _, _, err := c.Exchange(context.Background(), dnsQuestion("example.com", uint16(i))); err != nil {
					t.Fatal(err)
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("unsafe response cached: calls=%d", calls.Load())
			}
		})
	}
}

func TestDoHCachePreservesMixedPoisonAnswerForCaller(t *testing.T) {
	c := testDoHClient(t, func(_ *http.Request, q *mdns.Msg) (*mdns.Msg, error) {
		r := dnsAnswer(q, "195.175.254.2", 30)
		good := dnsAnswer(q, "203.0.113.9", 30)
		r.Answer = append(r.Answer, good.Answer...)
		return r, nil
	})
	_, err := c.LookupA(context.Background(), "example.com")
	var poisoned *PoisonError
	if !errors.As(err, &poisoned) {
		t.Fatalf("cache inspection hid the poison answer: %v", err)
	}
	if len(c.cache) != 0 {
		t.Fatal("mixed poisoned response was cached")
	}
}

func TestDoHNetworkResetIsolatesInFlightResponses(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	c := testDoHClient(t, func(r *http.Request, q *mdns.Msg) (*mdns.Msg, error) {
		if calls.Add(1) == 1 {
			select {
			case <-release:
				return dnsAnswer(q, "203.0.113.1", 30), nil
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return dnsAnswer(q, "203.0.113.2", 30), nil
	})
	first := make(chan error, 1)
	go func() { _, _, err := c.Exchange(context.Background(), dnsQuestion("example.com", 1)); first <- err }()
	waitDoHWaiters(t, c, 1)
	// Wait for the transport, not just the registered flight.
	deadline := time.Now().Add(time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("old-network transport did not start")
	}
	c.ResetCache()
	second, _, err := c.Exchange(context.Background(), dnsQuestion("example.com", 2))
	if err != nil || second.Answer[0].(*mdns.A).A.String() != "203.0.113.2" {
		t.Fatalf("new network joined old query: %v, %v", second, err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	third, _, err := c.Exchange(context.Background(), dnsQuestion("example.com", 3))
	if err != nil || third.Answer[0].(*mdns.A).A.String() != "203.0.113.2" || calls.Load() != 2 {
		t.Fatalf("old network filled new cache: %v, calls=%d err=%v", third, calls.Load(), err)
	}
}

func TestDoHPreferredEndpointKeepsFallbacks(t *testing.T) {
	var primary, backup atomic.Int32
	var failPrimary atomic.Bool
	c := testDoHClient(t, func(r *http.Request, q *mdns.Msg) (*mdns.Msg, error) {
		if r.URL.Host == "primary.test" {
			primary.Add(1)
			if failPrimary.Load() {
				return nil, errors.New("provider unavailable")
			}
		} else {
			backup.Add(1)
		}
		return dnsAnswer(q, "203.0.113.9", 30), nil
	})
	c.endpoints = append(c.endpoints, "https://backup.test/dns-query")
	c.preferred = c.endpoints[0]
	if _, _, err := c.Exchange(context.Background(), dnsQuestion("first.example", 1)); err != nil {
		t.Fatal(err)
	}
	if primary.Load() != 1 || backup.Load() != 0 {
		t.Fatalf("healthy provider triggered backup: primary=%d backup=%d", primary.Load(), backup.Load())
	}
	failPrimary.Store(true)
	if _, ep, err := c.Exchange(context.Background(), dnsQuestion("next.example", 2)); err != nil || ep != c.endpoints[1] {
		t.Fatalf("fallback missing: endpoint=%q err=%v", ep, err)
	}
}

func TestDoHSlowPreferredEndpointHedges(t *testing.T) {
	c := testDoHClient(t, func(r *http.Request, q *mdns.Msg) (*mdns.Msg, error) {
		if r.URL.Host == "primary.test" {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return dnsAnswer(q, "203.0.113.9", 30), nil
	})
	c.endpoints = append(c.endpoints, "https://backup.test/dns-query")
	c.preferred = c.endpoints[0]
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, ep, err := c.Exchange(ctx, dnsQuestion("example.com", 1)); err != nil || ep != c.endpoints[1] {
		t.Fatalf("slow provider prevented fallback: endpoint=%q err=%v", ep, err)
	}
}

func TestDoHCacheBoundAndShortestRecordTTL(t *testing.T) {
	c := testDoHClient(t, func(_ *http.Request, q *mdns.Msg) (*mdns.Msg, error) {
		return dnsAnswer(q, "203.0.113.9", 300), nil
	})
	for i := 0; i < dohCacheEntries+5; i++ {
		if _, _, err := c.Exchange(context.Background(), dnsQuestion(fmt.Sprintf("q%d.example", i), 1)); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.cache) != dohCacheEntries {
		t.Fatalf("cache size=%d", len(c.cache))
	}
	q := dnsQuestion("example.com", 1)
	r := dnsAnswer(q, "203.0.113.9", 300)
	if ttl := cacheableTTL(q, r, c.poison); ttl != dohCacheMaxTTL {
		t.Fatalf("cache TTL was not capped: %v", ttl)
	}
	cname, _ := mdns.NewRR("example.com. 7 IN CNAME alias.example.com.")
	r.Answer = append(r.Answer, cname)
	if ttl := cacheableTTL(q, r, c.poison); ttl != 7*time.Second {
		t.Fatalf("chain TTL=%v", ttl)
	}
}
