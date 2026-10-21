package engine

import (
	"context"
	"time"

	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
)

// Test measures explicitly requested endpoints through current OS routes. It
// never updates transport health, learned routes, network identity or policy.
func (e *Engine) Test(hosts []string) (*probe.Report, *ipc.RPCError) {
	e.mu.Lock()
	if !e.protection || e.state == StateStopped {
		e.mu.Unlock()
		return nil, &ipc.RPCError{Code: ipc.CodeNotRunning, Message: "Core protection is stopped"}
	}
	generation, parent, doh := e.sessionGeneration, e.sessionContextLocked(), e.doh
	fn := e.runProbe
	if fn == nil {
		fn = defaultProbe
	}
	if len(hosts) == 0 {
		hosts = e.controlHostsLocked()
	}
	hosts = append([]string(nil), hosts...)
	asn, isp := e.policy.ASN(), e.policy.ISPHint()
	e.mu.Unlock()
	if doh == nil {
		doh = offdns.NewDoHClient(offdns.DefaultPoisonSet())
		defer doh.Close()
	}
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	report := fn(ctx, doh, hosts)
	cancel()
	report.ASN, report.ISPHint = asn, isp
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.currentSessionLocked(generation) || parent.Err() != nil {
		return nil, &ipc.RPCError{Code: ipc.CodeNotRunning, Message: "Protection session changed during connection test"}
	}
	e.lastProbe = &report
	return &report, nil
}
