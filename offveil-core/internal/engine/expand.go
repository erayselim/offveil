package engine

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
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

func paintTargets(targets []ipc.TargetStatus, path, outcome string) {
	for i := range targets {
		if outcome != "" {
			targets[i].Outcome = outcome
		}
		if path != "" {
			targets[i].Path = path
		}
	}
}

// syncLastProbePaths aligns diagnostics "Last probe" with the session cascade path
// so support bundles do not show stale timeout→desync after a successful tunnel escalate.
func syncLastProbePaths(rep *probe.Report, path string, ok bool) {
	if rep == nil || path == "" {
		return
	}
	rep.Chosen = path
	for i := range rep.Results {
		rep.Results[i].Path = path
		if ok {
			rep.Results[i].OK = true
			if path == "tunnel" || path == "desync" || path == "direct" {
				// Keep Class as the original failure reason (useful for support),
				// but mark path/ok as the live cascade outcome.
			}
		}
	}
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

// handleExpandQuery is called from the DNS stub when a client looks up a host.
// Auto-expands TUN selected-routes for package siblings (legacy half-load CDN).
func (e *Engine) handleExpandQuery(host string) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.HasSuffix(host, ".arpa") || strings.HasSuffix(host, ".local") {
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
	// Initial resolve seeds already have /32 routes from capture start  - 
	// only suggest them again when they are the observed host (IP refresh).
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
