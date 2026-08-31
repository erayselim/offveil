package engine

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
)

const (
	expandMaxHosts  = 48
	expandResolveTO = 4 * time.Second
)

// ExpandInfo is half-load CDN expand diagnostics.
type ExpandInfo struct {
	Suggestions []ruleset.Suggestion `json:"suggestions,omitempty"`
	RoutesAdded int                  `json:"routes_added"`
	HostsSeen   int                  `json:"hosts_seen"`
}

func targetsFromDoc(doc ruleset.Document) []ipc.TargetStatus {
	seeds := doc.TargetSeeds()
	out := make([]ipc.TargetStatus, 0, len(seeds))
	for _, s := range seeds {
		out = append(out, ipc.TargetStatus{
			ID:      s.ID,
			Label:   s.Label,
			Outcome: "unknown",
			Path:    "none",
		})
	}
	return out
}

func setTarget(targets []ipc.TargetStatus, id, path, outcome string) {
	for i := range targets {
		if targets[i].ID != id {
			continue
		}
		if outcome != "" {
			targets[i].Outcome = outcome
		}
		if path != "" {
			targets[i].Path = path
		}
	}
}

func targetPath(targets []ipc.TargetStatus, id string) string {
	for _, t := range targets {
		if t.ID == id {
			return t.Path
		}
	}
	return ""
}

func applyProbeResult(targets []ipc.TargetStatus, doc ruleset.Document, host, class, path string) {
	pkgID := doc.PackageIDForHost(host)
	if pkgID == "" {
		return
	}
	for i := range targets {
		if targets[i].ID != pkgID {
			continue
		}
		if class != "" {
			targets[i].Outcome = class
		}
		if path != "" {
			targets[i].Path = path
		}
	}
}

// normalizeExpandHost strips a stub QNAME. false = never expand (PTR, mDNS, empty).
func normalizeExpandHost(host string) (string, bool) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.HasSuffix(host, ".arpa") || strings.HasSuffix(host, ".local") {
		return "", false
	}
	return host, true
}

// expandCandidate is the cheap OnQuery gate: skip goroutine unless the host
// belongs to a special package. Catch-all NRPT would otherwise spawn work for
// every system lookup.
func (e *Engine) expandCandidate(host string) bool {
	host, ok := normalizeExpandHost(host)
	if !ok {
		return false
	}
	e.mu.Lock()
	if !e.protection || e.rulesetSnap == nil {
		e.mu.Unlock()
		return false
	}
	doc := e.rulesetSnap.Doc
	e.mu.Unlock()
	pkg, ok := doc.MatchPackage(host)
	return ok && !pkg.IsCanary()
}

// handleExpandQuery is called from the DNS stub when a client looks up a host.
// Auto-expands sibling CDN hosts for legacy half-load (IMVU).
func (e *Engine) handleExpandQuery(host string) {
	host, ok := normalizeExpandHost(host)
	if !ok {
		return
	}

	e.mu.Lock()
	if !e.protection || e.rulesetSnap == nil || e.cap == nil {
		e.mu.Unlock()
		return
	}
	if e.expandSeen == nil {
		e.expandSeen = map[string]struct{}{}
	}
	if len(e.expandSeen) >= expandMaxHosts {
		e.mu.Unlock()
		return
	}
	if _, ok := e.expandSeen[host]; ok {
		e.mu.Unlock()
		return
	}
	doc := e.rulesetSnap.Doc
	if _, ok := doc.MatchPackage(host); !ok {
		e.mu.Unlock()
		return
	}

	already := make(map[string]struct{}, len(e.expandSeen)+8)
	for k := range e.expandSeen {
		already[k] = struct{}{}
	}
	// Resolve seeds are already known from capture start; only re-suggest
	// when the observed host is itself a seed (IP refresh).
	for _, rh := range doc.ResolveHosts() {
		if rh != host {
			already[rh] = struct{}{}
		}
	}
	capSess := e.cap
	doh := e.doh
	e.mu.Unlock()

	suggestions := doc.ExpandForHost(host, already)
	if len(suggestions) == 0 {
		e.mu.Lock()
		if e.expandSeen != nil {
			e.expandSeen[host] = struct{}{}
		}
		e.mu.Unlock()
		return
	}

	var hosts []string
	seenHost := map[string]struct{}{}
	for _, s := range suggestions {
		if _, ok := seenHost[s.Host]; ok {
			continue
		}
		seenHost[s.Host] = struct{}{}
		hosts = append(hosts, s.Host)
	}

	ctx, cancel := context.WithTimeout(context.Background(), expandResolveTO)
	defer cancel()
	var prefixes []netip.Prefix
	if doh != nil {
		for _, h := range hosts {
			addrs, err := doh.LookupAWithFallback(ctx, h)
			if err != nil {
				slog.Debug("engine: expand resolve failed", "host", h, "err", err)
				continue
			}
			for _, a := range addrs {
				if a.Is4() {
					prefixes = append(prefixes, netip.PrefixFrom(a, 32))
				}
			}
		}
	}

	added := 0
	if len(prefixes) > 0 {
		n, err := capSess.AddPrefixes(prefixes)
		if err != nil {
			slog.Debug("engine: expand routes", "err", err, "added", n)
		}
		added = n
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.protection {
		return
	}
	if e.expandSeen == nil {
		e.expandSeen = map[string]struct{}{}
	}
	e.expandSeen[host] = struct{}{}
	for _, h := range hosts {
		e.expandSeen[h] = struct{}{}
	}
	e.expandSuggestions = append(suggestions, e.expandSuggestions...)
	if len(e.expandSuggestions) > 32 {
		e.expandSuggestions = e.expandSuggestions[:32]
	}
	e.expandRoutesAdded += added
	if e.captureInfo != nil {
		cp := capSess.Info()
		e.captureInfo = &cp
	}
	slog.Info("engine: domain expand",
		"observed", host,
		"suggestions", len(suggestions),
		"routes_added", added,
	)
}

func (e *Engine) expandInfoLocked() *ExpandInfo {
	if e.expandRoutesAdded == 0 && len(e.expandSuggestions) == 0 && len(e.expandSeen) == 0 {
		return nil
	}
	sug := append([]ruleset.Suggestion(nil), e.expandSuggestions...)
	return &ExpandInfo{
		Suggestions: sug,
		RoutesAdded: e.expandRoutesAdded,
		HostsSeen:   len(e.expandSeen),
	}
}

// HandleExpandQueryForTest runs domain expand synchronously (unit tests).
func (e *Engine) HandleExpandQueryForTest(host string) {
	e.handleExpandQuery(host)
}
