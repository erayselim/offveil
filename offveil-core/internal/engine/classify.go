package engine

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/appdir"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

// DPI classes for the current physical network.
const (
	DPINone    = "none"    // persistent canaries open directly: DNS layer is enough
	DPIPresent = "present" // a persistent canary is reset, dropped or throttled
	DPIOffline = "offline" // neutral controls fail directly: no usable internet
	DPIUnknown = "unknown"
)

// slowHandshake marks throttling: a TLS handshake this slow on an otherwise
// healthy line is how SNI throttling shows up (OONI, 2023 and 2025 reports).
const slowHandshake = 3 * time.Second

const classifyBudget = 7 * time.Second

// forceLayerFlag is a diagnostics switch: when a file with this name exists in
// the machine data root, the TCP layer starts even on a network that measures
// as unfiltered. CI uses it to exercise the TUN path on runners without DPI.
// It only ever adds protection, so a spoofed flag cannot weaken anything.
const forceLayerFlag = "force-tcp-layer"

func forcedTCPLayer() bool {
	_, err := os.Stat(filepath.Join(appdir.Root(), forceLayerFlag))
	return err == nil
}

// HostCheck is one measured destination. Only ruleset hosts appear here.
type HostCheck struct {
	Host  string `json:"host"`
	Group string `json:"group,omitempty"`
	Path  string `json:"path"`
	Class string `json:"class"`
	MS    int64  `json:"ms"`
}

// Classification is the network's filtering verdict.
type Classification struct {
	DPI       string      `json:"dpi"`
	CheckedAt string      `json:"checked_at"`
	Checks    []HostCheck `json:"checks,omitempty"`
}

// DirectProbe measures one host on the physical interface.
type DirectProbe func(ctx context.Context, host string) tunnel.FailSignal

// ClassifyFunc lets tests replace physical measurements.
type ClassifyFunc func(ctx context.Context, probe DirectProbe, controls []string, groups []ruleset.CanaryGroup) Classification

func newDirectProbe(egress string, resolve func(context.Context, string) (netip.Addr, error)) DirectProbe {
	return func(ctx context.Context, host string) tunnel.FailSignal {
		return tunnel.ProbeDirectTLS(ctx, egress, resolve, host)
	}
}

func measure(ctx context.Context, probe DirectProbe, host, group string) HostCheck {
	start := time.Now()
	sig := probe(ctx, host)
	took := time.Since(start)
	class := string(sig.Class)
	if sig.Class == tunnel.FailOK && took >= slowHandshake {
		class = "slow"
	}
	return HostCheck{Host: host, Group: group, Path: "direct", Class: class, MS: took.Milliseconds()}
}

// filtered reports a canary result that looks like censorship rather than an
// unrelated outage. Certificate errors are included: they follow DNS or
// transparent-proxy tampering on the physical path.
func filtered(class string) bool {
	switch class {
	case string(tunnel.FailOK), string(tunnel.FailConfig):
		return false
	}
	return true
}

// classifyNetwork probes neutral controls and the first host of each
// persistent group in parallel on the physical interface.
func classifyNetwork(ctx context.Context, probe DirectProbe, controls []string, groups []ruleset.CanaryGroup) Classification {
	ctx, cancel := context.WithTimeout(ctx, classifyBudget)
	defer cancel()
	type job struct{ host, group string }
	var jobs []job
	for _, host := range controls {
		jobs = append(jobs, job{host, ""})
	}
	for _, group := range groups {
		if len(group.ProbeHosts) > 0 {
			jobs = append(jobs, job{group.ProbeHosts[0], group.ID})
		}
	}
	checks := make([]HostCheck, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Go(func() { checks[i] = measure(ctx, probe, j.host, j.group) })
	}
	wg.Wait()
	out := Classification{DPI: DPIUnknown, CheckedAt: time.Now().UTC().Format(time.RFC3339), Checks: checks}
	controlsOK, canaries, blocked := 0, 0, 0
	for _, check := range checks {
		if check.Group == "" {
			if check.Class == string(tunnel.FailOK) {
				controlsOK++
			}
			continue
		}
		canaries++
		if filtered(check.Class) {
			blocked++
		}
	}
	switch {
	case len(controls) >= 2 && controlsOK < 2:
		out.DPI = DPIOffline
	case canaries == 0:
		out.DPI = DPIUnknown
	case blocked > 0:
		out.DPI = DPIPresent
	default:
		out.DPI = DPINone
	}
	return out
}
