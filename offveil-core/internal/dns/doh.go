package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

// Default DoH upstreams (bootstrap by IP - no system DNS dependency).
var defaultDoHEndpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://1.0.0.1/dns-query",
	"https://8.8.8.8/dns-query",
	"https://9.9.9.9/dns-query",
}

const (
	dohExchangeBudget = 2 * time.Second // Firefox TRR uses ~1.5s; fail fast → plain
	dohDialTimeout    = 1500 * time.Millisecond
	dohFailThreshold  = 3
	dohSkipCooldown   = 60 * time.Second
)

// DoHClient resolves via DNS-over-HTTPS without using the system resolver.
type DoHClient struct {
	endpoints []string
	client    *http.Client
	poison    *PoisonSet

	mu         sync.Mutex
	poisoned   int
	failStreak int
	skipUntil  time.Time
	mode       string // doh | plain_skip | recovering
}

// NewDoHClient builds a bootstrap DoH client.
func NewDoHClient(poison *PoisonSet) *DoHClient {
	if poison == nil {
		poison = DefaultPoisonSet()
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   dohDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   dohDialTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: dohDialTimeout,
	}
	return &DoHClient{
		endpoints: append([]string{}, defaultDoHEndpoints...),
		client: &http.Client{
			Timeout:   dohExchangeBudget,
			Transport: transport,
		},
		poison: poison,
		mode:   "doh",
	}
}

// PoisonHits returns how many DoH answers matched censorship fingerprints.
func (c *DoHClient) PoisonHits() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.poisoned
}

// Mode returns the current DoH transport posture for diagnostics.
func (c *DoHClient) Mode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.skipUntil) {
		return "plain_skip"
	}
	if c.mode == "" {
		return "doh"
	}
	return c.mode
}

type dohResult struct {
	resp *mdns.Msg
	ep   string
	err  error
}

func (c *DoHClient) noteSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failStreak = 0
	c.skipUntil = time.Time{}
	c.mode = "doh"
}

func (c *DoHClient) noteFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failStreak++
	if c.failStreak >= dohFailThreshold {
		c.skipUntil = time.Now().Add(dohSkipCooldown)
		c.mode = "plain_skip"
		slog.Warn("doh: circuit open, plain UDP for cooldown",
			"streak", c.failStreak, "cooldown", dohSkipCooldown.String())
	}
}

func (c *DoHClient) shouldSkip() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.skipUntil.IsZero() {
		return false
	}
	if time.Now().Before(c.skipUntil) {
		return true
	}
	// Cooldown elapsed - one recovering attempt.
	c.skipUntil = time.Time{}
	c.mode = "recovering"
	c.failStreak = dohFailThreshold - 1 // one more fail re-opens
	return false
}

// Exchange races DoH endpoints in parallel; first success wins.
// After consecutive failures, skips DoH briefly (Firefox TRR Confirmation pattern).
func (c *DoHClient) Exchange(ctx context.Context, msg *mdns.Msg) (*mdns.Msg, string, error) {
	if c.shouldSkip() {
		return nil, "", fmt.Errorf("DoH skipped (circuit open)")
	}

	packed, err := msg.Pack()
	if err != nil {
		return nil, "", fmt.Errorf("pack: %w", err)
	}
	if len(c.endpoints) == 0 {
		return nil, "", fmt.Errorf("no DoH endpoints configured")
	}

	ctx, cancel := context.WithTimeout(ctx, dohExchangeBudget)
	defer cancel()

	ch := make(chan dohResult, len(c.endpoints))
	for _, ep := range c.endpoints {
		go func(ep string) {
			resp, err := c.exchangeOne(ctx, ep, packed)
			ch <- dohResult{resp: resp, ep: ep, err: err}
		}(ep)
	}

	var lastErr error
	remaining := len(c.endpoints)
	for remaining > 0 {
		select {
		case <-ctx.Done():
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			c.noteFailure()
			return nil, "", fmt.Errorf("DoH timeout: %w", lastErr)
		case r := <-ch:
			remaining--
			if r.err != nil {
				lastErr = r.err
				continue
			}
			cancel() // stop siblings
			c.noteSuccess()
			return r.resp, r.ep, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all DoH endpoints failed")
	}
	c.noteFailure()
	return nil, "", lastErr
}

func (c *DoHClient) exchangeOne(ctx context.Context, endpoint string, packed []byte) (*mdns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "offveil-core/doh")

	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", endpoint, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil {
		return nil, fmt.Errorf("%s read: %w", endpoint, err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", endpoint, res.StatusCode)
	}
	out := new(mdns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("%s unpack: %w", endpoint, err)
	}
	return out, nil
}

// LookupA resolves A records via DoH. Poison answers are rejected.
func (c *DoHClient) LookupA(ctx context.Context, host string) ([]netip.Addr, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(host), mdns.TypeA)
	msg.RecursionDesired = true

	resp, ep, err := c.Exchange(ctx, msg)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != mdns.RcodeSuccess && resp.Rcode != mdns.RcodeNameError {
		return nil, fmt.Errorf("DoH %s rcode=%d", ep, resp.Rcode)
	}

	var addrs []netip.Addr
	for _, rr := range resp.Answer {
		a, ok := rr.(*mdns.A)
		if !ok {
			continue
		}
		ip4 := a.A.To4()
		if ip4 == nil {
			continue
		}
		addr := netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
		if id, hit := c.poison.Match(addr); hit {
			c.mu.Lock()
			c.poisoned++
			c.mu.Unlock()
			return nil, &PoisonError{
				Host:  host,
				Addr:  addr,
				ID:    id,
				Via:   "doh:" + ep,
				Class: "dns_poison",
			}
		}
		addrs = append(addrs, addr)
	}
	slog.Debug("doh: lookup ok", "host", host, "via", ep, "addrs", len(addrs))
	return addrs, nil
}

// LookupAWithFallback tries DoH first; on failure uses plain UDP to public
// resolvers (not the system resolver - that loops into our stub after leak-guard).
func (c *DoHClient) LookupAWithFallback(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := c.LookupA(ctx, host)
	if err == nil {
		return addrs, nil
	}
	slog.Warn("doh: lookup failed, trying plain UDP DNS", "host", host, "err", err)

	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(host), mdns.TypeA)
	msg.RecursionDesired = true
	resp, ep, plainErr := ExchangePlain(ctx, msg, nil)
	if plainErr != nil {
		return nil, fmt.Errorf("DoH failed (%v); plain DNS: %w", err, plainErr)
	}
	if resp.Rcode != mdns.RcodeSuccess && resp.Rcode != mdns.RcodeNameError {
		return nil, fmt.Errorf("plain DNS %s rcode=%d", ep, resp.Rcode)
	}

	var out []netip.Addr
	for _, rr := range resp.Answer {
		a, ok := rr.(*mdns.A)
		if !ok {
			continue
		}
		ip4 := a.A.To4()
		if ip4 == nil {
			continue
		}
		addr := netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
		if id, hit := c.poison.Match(addr); hit {
			c.mu.Lock()
			c.poisoned++
			c.mu.Unlock()
			return nil, &PoisonError{
				Host:  host,
				Addr:  addr,
				ID:    id,
				Via:   "plain:" + ep,
				Class: "dns_poison",
			}
		}
		out = append(out, addr)
	}
	slog.Info("dns: using plain UDP (DoH unavailable)", "host", host, "via", ep, "addrs", len(out))
	return out, nil
}
