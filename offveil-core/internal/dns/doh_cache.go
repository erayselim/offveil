package dns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	dohCacheEntries = 256
	dohCacheMaxTTL  = time.Minute
	dohCacheMaxSize = 4096
)

type dohCacheEntry struct {
	response *mdns.Msg
	endpoint string
	stored   time.Time
	expires  time.Time
}

type dohFlight struct {
	done       chan struct{}
	cancel     context.CancelFunc
	waiters    int
	generation uint64
	response   *mdns.Msg
	endpoint   string
	err        error
}

// Exchange coalesces identical questions and briefly caches positive, clean
// answers. Full wire questions (including flags/EDNS) are keyed without the ID.
// Every caller gets a private copy with its own ID and can cancel independently.
func (c *DoHClient) Exchange(ctx context.Context, msg *mdns.Msg) (*mdns.Msg, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if msg == nil {
		return nil, "", fmt.Errorf("nil DNS question")
	}
	query := msg.Copy()
	share := query.Opcode == mdns.OpcodeQuery && !query.Response && len(query.Question) == 1 && query.IsTsig() == nil
	if share {
		query.Id = 0
	}
	packed, err := query.Pack()
	if err != nil {
		return nil, "", fmt.Errorf("pack: %w", err)
	}
	if !share {
		return c.exchange(ctx, packed)
	}
	key := string(packed)
	now := time.Now()
	c.queriesMu.Lock()
	if cached, ok := c.cache[key]; ok {
		if now.Before(cached.expires) {
			out := cached.response.Copy()
			ageDNSResponse(out, uint32(now.Sub(cached.stored)/time.Second))
			out.Id = msg.Id
			c.queriesMu.Unlock()
			return out, cached.endpoint, nil
		}
		delete(c.cache, key)
	}
	flight := c.flights[key]
	if flight == nil {
		// A short-lived caller must not cancel another caller's DNS resolution.
		work, cancel := context.WithTimeout(context.WithoutCancel(ctx), dohExchangeBudget)
		flight = &dohFlight{done: make(chan struct{}), cancel: cancel, generation: c.generation}
		if c.flights == nil {
			c.flights = make(map[string]*dohFlight)
		}
		c.flights[key] = flight
		go c.resolveFlight(work, key, packed, query, flight)
	}
	flight.waiters++
	c.queriesMu.Unlock()
	defer c.releaseFlight(key, flight)

	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case <-flight.done:
		if flight.response == nil {
			return nil, flight.endpoint, flight.err
		}
		out := flight.response.Copy()
		out.Id = msg.Id
		return out, flight.endpoint, flight.err
	}
}

func (c *DoHClient) resolveFlight(ctx context.Context, key string, packed []byte, query *mdns.Msg, f *dohFlight) {
	defer f.cancel()
	response, endpoint, err := c.exchange(ctx, packed)
	c.queriesMu.Lock()
	defer c.queriesMu.Unlock()
	f.response, f.endpoint, f.err = response, endpoint, err
	if c.flights[key] == f {
		delete(c.flights, key)
	}
	if err == nil && ctx.Err() == nil && f.generation == c.generation {
		if ttl := cacheableTTL(query, response, c.poison); ttl > 0 {
			now := time.Now()
			if c.cache == nil {
				c.cache = make(map[string]dohCacheEntry)
			}
			// Remove expired entries first, then evict the nearest expiry.
			var oldestKey string
			var oldest time.Time
			for k, entry := range c.cache {
				if !now.Before(entry.expires) {
					delete(c.cache, k)
					continue
				}
				if oldest.IsZero() || entry.expires.Before(oldest) {
					oldestKey, oldest = k, entry.expires
				}
			}
			if len(c.cache) >= dohCacheEntries {
				delete(c.cache, oldestKey)
			}
			c.cache[key] = dohCacheEntry{response.Copy(), endpoint, now, now.Add(ttl)}
		}
	}
	close(f.done)
}

func (c *DoHClient) releaseFlight(key string, f *dohFlight) {
	c.queriesMu.Lock()
	defer c.queriesMu.Unlock()
	f.waiters--
	if f.waiters == 0 {
		if c.flights[key] == f {
			delete(c.flights, key)
		}
		f.cancel()
	}
}

// ResetCache also detaches old in-flight requests so their results cannot fill
// the new network's cache or be joined by questions on the new network.
func (c *DoHClient) ResetCache() {
	c.queriesMu.Lock()
	c.generation++
	c.cache = nil
	c.flights = nil
	c.queriesMu.Unlock()
	c.mu.Lock()
	c.preferred = ""
	c.failStreak = 0
	c.skipUntil = time.Time{}
	c.mode = "doh"
	c.mu.Unlock()
}

// Close releases cached answers, in-flight work and idle HTTPS connections.
func (c *DoHClient) Close() {
	c.queriesMu.Lock()
	for _, flight := range c.flights {
		flight.cancel()
	}
	c.queriesMu.Unlock()
	c.ResetCache()
	c.client.CloseIdleConnections()
}

func cacheableTTL(query, response *mdns.Msg, poison *PoisonSet) time.Duration {
	if response == nil || !response.Response || response.Truncated || response.IsTsig() != nil ||
		response.Opcode != query.Opcode || response.Rcode != mdns.RcodeSuccess ||
		len(response.Question) != 1 || len(response.Answer) == 0 || response.Len() > dohCacheMaxSize {
		return 0
	}
	q, r := query.Question[0], response.Question[0]
	if !strings.EqualFold(q.Name, r.Name) || q.Qtype != r.Qtype || q.Qclass != r.Qclass {
		return 0
	}
	// Never persist censorship fingerprints, SERVFAIL, NXDOMAIN or empty answers.
	for _, rr := range response.Answer {
		if a, ok := rr.(*mdns.A); ok {
			if ip, valid := netip.AddrFromSlice(a.A); valid {
				if _, poisoned := poison.Match(ip.Unmap()); poisoned {
					return 0
				}
			}
		}
	}
	ttl := dohCacheMaxTTL
	for _, section := range [][]mdns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == mdns.TypeOPT {
				continue
			}
			if t := time.Duration(rr.Header().Ttl) * time.Second; t < ttl {
				ttl = t
			}
		}
	}
	return ttl
}

func ageDNSResponse(response *mdns.Msg, age uint32) {
	for _, section := range [][]mdns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == mdns.TypeOPT {
				continue
			}
			if rr.Header().Ttl > age {
				rr.Header().Ttl -= age
			} else {
				rr.Header().Ttl = 0
			}
		}
	}
}
