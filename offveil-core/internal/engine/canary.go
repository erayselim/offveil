package engine

import (
	"context"
	"log/slog"
	"time"

	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
)

const canaryInterval = 5 * time.Minute

func (e *Engine) maybeCanary() {
	e.mu.Lock()
	if !e.lastCanaryAt.IsZero() && time.Since(e.lastCanaryAt) < canaryInterval {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	e.probeCanary()
}

// ProbeCanaryForTest runs the background canary probe synchronously.
func (e *Engine) ProbeCanaryForTest() {
	e.probeCanary()
}

func (e *Engine) probeCanary() {
	e.mu.Lock()
	if !e.protection || e.state == StateStopped || e.state == StateStopping || e.rulesetSnap == nil {
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
	e.mu.Unlock()

	if doh == nil {
		doh = offdns.NewDoHClient(offdns.DefaultPoisonSet())
	}
	pctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	rep := probeFn(pctx, doh, hosts)
	cancel()

	e.mu.Lock()
	if !e.protection || e.state == StateStopped || e.state == StateStopping {
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
		e.lastProbe.Results = append(append([]probe.Result{}, e.lastProbe.Results...), rep.Results...)
	}
	want, _ := splitSpecialHosts(e.rulesetSnap.Doc, e.targets, e.policy)
	changed := !sameHostSet(want, e.dataplaneTunnel)
	e.lastCanaryAt = time.Now()
	e.mu.Unlock()

	if !changed {
		return
	}
	slog.Info("engine: canary path changed, rebuilding dataplane", "tunnel_hosts", len(want))
	e.SelfHeal("canary_tunnel")
}
