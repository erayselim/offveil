package policy

import (
	"sync"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

// Path values match contracts.md §3.1.
const (
	PathDirect = "direct"
	PathDesync = "desync"
	PathTunnel = "tunnel"
	PathNone   = "none"
)

// Entry is one domain → outbound cache record (contracts.md §3.3).
type Entry struct {
	Key        string // asn:N|domain
	Domain     string
	Path       string
	Class      string // open | dpi_reset | timeout | ssl_err | …
	StrategyID string
	UpdatedAt  time.Time
	TTL        time.Duration
}

// Store is an in-memory policy cache keyed by ASN + domain.
type Store struct {
	mu          sync.Mutex
	entries     map[string]Entry
	asn         string
	ispHint     string
	fingerprint string
}

// NewStore creates an empty policy cache.
func NewStore() *Store {
	return &Store{
		entries: make(map[string]Entry),
		asn:     "unknown",
	}
}

// ASN returns the current ISS ASN used for cache keys.
func (s *Store) ASN() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asn
}

// ISPHint returns a human-readable ISP hint (diagnostics / test).
func (s *Store) ISPHint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ispHint
}

// Fingerprint returns the local egress fingerprint.
func (s *Store) Fingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fingerprint
}

// ObserveNetwork updates ASN / fingerprint. Returns true if cache was invalidated
// because ISS/ASN or local egress identity changed (contracts.md §3.3).
func (s *Store) ObserveNetwork(info netinfo.Info) (invalidated bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	asn := netinfo.NormalizeASN(info.ASN)
	fp := info.Fingerprint
	if fp == "" {
		fp = "unknown"
	}
	changed := false
	if s.asn != "" && s.asn != "unknown" && asn != "unknown" && s.asn != asn {
		changed = true
	}
	if s.fingerprint != "" && s.fingerprint != "offline" && fp != "offline" && s.fingerprint != fp {
		changed = true
	}
	// First observation: adopt without wiping (empty store).
	if s.fingerprint == "" && s.asn == "unknown" {
		changed = false
	}
	if changed {
		s.entries = make(map[string]Entry)
	}
	s.asn = asn
	if info.ISPHint != "" {
		s.ispHint = info.ISPHint
	}
	s.fingerprint = fp
	return changed
}

// Invalidate clears all cached path decisions (manual / test).
func (s *Store) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[string]Entry)
}

// Put stores a probe/cascade decision under the current ASN.
func (s *Store) Put(domain, path, class, strategyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putLocked(domain, path, class, strategyID, time.Now().UTC(), 0)
}

// PutWithTTL stores a decision with an explicit TTL (0 → class-based default).
func (s *Store) PutWithTTL(domain, path, class, strategyID string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putLocked(domain, path, class, strategyID, time.Now().UTC(), ttl)
}

func (s *Store) putLocked(domain, path, class, strategyID string, at time.Time, ttl time.Duration) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if ttl <= 0 {
		ttl = TTLFor(path, class)
	}
	s.entries[domain] = Entry{
		Key:        cacheKey(s.asn, domain),
		Domain:     domain,
		Path:       path,
		Class:      class,
		StrategyID: strategyID,
		UpdatedAt:  at,
		TTL:        ttl,
	}
}

// TTLFor returns per-path/class TTL (contracts default 86400 for stable open).
func TTLFor(path, class string) time.Duration {
	switch class {
	case "retry":
		return 15 * time.Minute
	case "timeout":
		return 30 * time.Minute
	case "throttle_suspect":
		return 1 * time.Hour
	case "dpi_reset", "ssl_err", "dns_poison":
		return 6 * time.Hour
	case "ip_drop":
		return 2 * time.Hour
	}
	switch path {
	case PathTunnel:
		return 6 * time.Hour
	case PathDesync:
		return 6 * time.Hour
	case PathDirect:
		return 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}

func cacheKey(asn, domain string) string {
	if asn == "" {
		asn = "unknown"
	}
	return "asn:" + asn + "|" + domain
}

// OnDesyncFail implements desync.Sink: desync exhausted / failed → prefer tunnel.
func (s *Store) OnDesyncFail(sig desync.FailSignal) {
	class := string(sig.Class)
	switch sig.Class {
	case desync.FailReset:
		class = "dpi_reset"
	case desync.FailSSLErr:
		class = "ssl_err"
	case desync.FailTimeout:
		class = "timeout"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	at := sig.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	s.putLocked(sig.Target, PathTunnel, class, sig.StrategyID, at, 0)
}

// OnDesyncOK implements desync.Sink: mark path=desync.
func (s *Store) OnDesyncOK(target, strategyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putLocked(target, PathDesync, "open", strategyID, time.Now().UTC(), 0)
}

// OnTunnelOK implements tunnel.Sink: mark path=tunnel.
func (s *Store) OnTunnelOK(target, providerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putLocked(target, PathTunnel, "open", providerID, time.Now().UTC(), 0)
}

// OnTunnelFail implements tunnel.Sink: keep path=tunnel but class=retry.
func (s *Store) OnTunnelFail(sig tunnel.FailSignal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at := sig.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	s.putLocked(sig.Target, PathTunnel, "retry", sig.ProviderID, at, 0)
}

// Lookup returns a cached entry if present and not expired.
func (s *Store) Lookup(domain string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[domain]
	if !ok {
		return Entry{}, false
	}
	if e.TTL > 0 && time.Since(e.UpdatedAt) > e.TTL {
		delete(s.entries, domain)
		return Entry{}, false
	}
	return e, true
}

// ExpiredDomains returns domains whose TTL has elapsed (and drops them).
// Engine uses this for silent re-probe (contracts.md §3.3).
func (s *Store) ExpiredDomains() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	for d, e := range s.entries {
		if e.TTL > 0 && now.Sub(e.UpdatedAt) > e.TTL {
			out = append(out, d)
			delete(s.entries, d)
		}
	}
	return out
}

// Domains returns a snapshot of cached domain keys (not expired).
func (s *Store) Domains() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.entries))
	now := time.Now()
	for d, e := range s.entries {
		if e.TTL > 0 && now.Sub(e.UpdatedAt) > e.TTL {
			continue
		}
		out = append(out, d)
	}
	return out
}

// HintFor returns outbound path hint for status (desync|tunnel|direct|"").
func (s *Store) HintFor(domain string) string {
	if e, ok := s.Lookup(domain); ok {
		return e.Path
	}
	return ""
}
