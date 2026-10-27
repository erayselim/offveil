package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/cleanup"
	"github.com/erayselim/offveil/offveil-core/internal/desync"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
	"github.com/erayselim/offveil/offveil-core/internal/policy"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
	"github.com/erayselim/offveil/offveil-core/internal/repair"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func activeBackgroundEngine(t *testing.T) *Engine {
	t.Helper()
	e := New(cleanup.NewRegistry())
	e.beginSessionLocked()
	e.state, e.protection = StateActive, true
	rs := ruleset.MustLoadEmbedded()
	e.rulesetSnap = &rs
	e.policy.ObserveNetwork(netinfo.Info{ASN: "9121", Fingerprint: "network-a"})
	e.networkFingerprint = "network-a"
	e.tun = tunnel.NewFakeSession(tunnel.Info{Up: true, Healthy: true, Mode: "remote", ProviderID: tunnel.ProviderWARP})
	t.Cleanup(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.cancelSessionLocked()
	})
	return e
}

func awaitBackground(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("background operation did not reach expected stage")
	}
}

func replaceBackgroundSession(e *Engine) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.beginSessionLocked()
	e.policy = policy.NewStore()
	e.policy.ObserveNetwork(netinfo.Info{ASN: "13335", Fingerprint: "network-b"})
}

func TestReprobeDiscardsPreviousSessionNetworkAndProbe(t *testing.T) {
	for _, stage := range []string{"network", "probe"} {
		t.Run(stage, func(t *testing.T) {
			e := activeBackgroundEngine(t)
			e.policy.OnDesyncFail(desync.FailSignal{
				Target: "blocked.test", Class: desync.FailReset,
				At: time.Now().Add(-24 * time.Hour),
			})
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			e.lookupNet = func(context.Context) netinfo.Info {
				if stage == "network" {
					close(entered)
					<-release
				}
				return netinfo.Info{ASN: "9121", Fingerprint: "network-a"}
			}
			e.runProbe = func(context.Context, *offdns.DoHClient, []string) probe.Report {
				close(entered)
				<-release
				return probe.Report{Results: []probe.Result{{Target: "blocked.test", Class: probe.ClassDPIReset}}}
			}
			go func() { defer close(done); e.silentReprobe() }()
			releaseWork := sync.OnceFunc(func() { close(release); <-done })
			defer releaseWork()
			awaitBackground(t, entered)
			replaceBackgroundSession(e)
			releaseWork()
			if e.policy.ASN() != "13335" || e.policy.Fingerprint() != "network-b" {
				t.Fatal("old network lookup replaced new network identity")
			}
			if _, ok := e.policy.Lookup("blocked.test"); ok {
				t.Fatal("old probe wrote a policy decision into the new session")
			}
		})
	}
}

func TestReprobeDetectedNetworkChangeStillRebuilds(t *testing.T) {
	e := activeBackgroundEngine(t)
	// A recent heal must postpone this change, not drop it after adoption.
	e.lastHealAt = time.Now().Add(-healMinInterval + 3*time.Second)
	e.lookupNet = func(context.Context) netinfo.Info { return netinfo.Info{ASN: "9121", Fingerprint: "network-b"} }
	e.loadRuleset = func(context.Context) (ruleset.Snapshot, error) { return ruleset.MustLoadEmbedded(), nil }
	started := make(chan struct{})
	e.startCapture = func(capture.Config) (capture.Session, error) {
		close(started)
		return nil, errors.New("injected capture failure; no real network changes")
	}
	e.silentReprobe()
	awaitBackground(t, started)
	e.healMu.Lock()
	e.healMu.Unlock()
	if e.healCount != 1 {
		t.Fatalf("already-observed change did not trigger rebuild: %d", e.healCount)
	}
}

func TestRepairSerializesStartAndKeepsStatusReadable(t *testing.T) {
	e := New(cleanup.NewRegistry())
	entered, release := make(chan struct{}), make(chan struct{})
	repaired, started, startDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.runRepair = func() repair.Result {
		close(entered)
		<-release
		return repair.Result{}
	}
	e.loadRuleset = func(context.Context) (ruleset.Snapshot, error) { return ruleset.MustLoadEmbedded(), nil }
	e.startCapture = func(capture.Config) (capture.Session, error) {
		close(started)
		return nil, errors.New("fake capture")
	}
	go func() { defer close(repaired); _, _ = e.Repair() }()
	releaseRepair := sync.OnceFunc(func() { close(release); <-repaired })
	defer releaseRepair()
	awaitBackground(t, entered)
	if status := e.Status(); status.State != StateStopped {
		t.Fatalf("repair snapshot unavailable: %+v", status)
	}
	go func() { defer close(startDone); _, _ = e.Start("auto") }()
	select {
	case <-started:
		t.Error("start overlapped network repair")
	case <-time.After(100 * time.Millisecond):
	}
	releaseRepair()
	awaitBackground(t, startDone)
	awaitBackground(t, started)
}

func TestStatusReportsRequiredGatewayExitAsDegraded(t *testing.T) {
	e := activeBackgroundEngine(t)
	if e.Status().Health != "ok" {
		t.Fatal("healthy sidecar reported degraded")
	}
	_ = e.tun.Close()
	st := e.Status()
	if st.State != StateDegraded || st.Health != "degraded" || st.LastError == nil {
		t.Fatalf("sidecar exit not reflected: %+v", st)
	}
}
