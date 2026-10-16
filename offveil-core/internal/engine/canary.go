package engine

import (
	"context"
	"log/slog"
	"time"

	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
)

const canaryInterval = 5 * time.Minute

func (e *Engine) maybeCanarySession(generation uint64) {
	e.mu.Lock()
	if !e.lastCanaryAt.IsZero() && time.Since(e.lastCanaryAt) < canaryInterval {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	e.probeCanarySession(generation)
}

// ProbeCanaryForTest runs the background canary probe synchronously.
func (e *Engine) ProbeCanaryForTest() {
	e.probeCanary()
}

func (e *Engine) probeCanary() {
	e.mu.Lock()
	generation := e.sessionGeneration
	e.mu.Unlock()
	e.probeCanarySession(generation)
}

func (e *Engine) probeCanarySession(generation uint64) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.rulesetSnap == nil {
		e.mu.Unlock()
		return
	}
	hosts := e.rulesetSnap.Doc.CanaryProbeHosts()
	if len(hosts) == 0 {
		e.lastCanaryAt = time.Now()
		e.mu.Unlock()
		return
	}
	doh := e.doh
	probeFn := e.runProbe
	if probeFn == nil {
		probeFn = defaultProbe
	}
	ctx := e.sessionContextLocked()
	e.mu.Unlock()

	if doh == nil {
		doh = offdns.NewDoHClient(offdns.DefaultPoisonSet())
		defer doh.Close()
	}
	pctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	rep := probeFn(pctx, doh, hosts)
	cancel()

	e.mu.Lock()
	if !e.currentSessionLocked(generation) {
		e.mu.Unlock()
		return
	}
	for _, r := range rep.Results {
		path := probe.CanaryPath(r.Class, r.Path)
		e.policy.Put(r.Target, path, string(r.Class), "probe:canary")
		slog.Info("engine: canary probe", "target", r.Target, "class", r.Class, "path", path)
	}
	if e.lastProbe == nil {
		cp := rep
		e.lastProbe = &cp
	} else {
		// Keep the last result per host, preserving non-canary probe rows.
		// Test returns its report to an IPC caller after releasing e.mu, so
		// never mutate a previously published report's backing slice.
		next := *e.lastProbe
		next.Results = append([]probe.Result(nil), next.Results...)
		positions := make(map[string]int, len(next.Results))
		for i, r := range next.Results {
			positions[r.Target] = i
		}
		for _, r := range rep.Results {
			if i, ok := positions[r.Target]; ok {
				next.Results[i] = r
			} else {
				positions[r.Target] = len(next.Results)
				next.Results = append(next.Results, r)
			}
		}
		e.lastProbe = &next
	}
	want, _ := splitSpecialHosts(e.rulesetSnap.Doc, e.targets, e.policy)
	changed := !sameHostSet(want, e.dataplaneTunnel)
	e.lastCanaryAt = time.Now()
	lifecycle := e.lifecycleGeneration
	e.mu.Unlock()

	if !changed {
		return
	}
	slog.Info("engine: canary path changed, rebuilding dataplane", "tunnel_hosts", len(want))
	e.selfHeal("canary_tunnel", lifecycle, generation, false)
}
