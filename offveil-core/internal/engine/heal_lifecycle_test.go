package engine

import (
	"context"
	"errors"
	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/cleanup"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
	"github.com/erayselim/offveil/offveil-core/internal/repair"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"sync/atomic"
	"testing"
	"time"
)

func TestUserLifecycleRequestCancelsPendingHeal(t *testing.T) {
	for _, action := range []string{"stop", "repair"} {
		t.Run(action, func(t *testing.T) {
			e := New(cleanup.NewRegistry())
			e.state, e.layer = StateActive, layerSelective
			e.protection = true
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			e.lookupNet = func(context.Context) netinfo.Info {
				close(entered)
				<-release
				return netinfo.Info{ASN: "9121", Fingerprint: "test-network"}
			}
			e.loadRuleset = func(context.Context) (ruleset.Snapshot, error) { return ruleset.MustLoadEmbedded(), nil }
			e.runRepair = func() repair.Result { return repair.Result{} }
			var starts atomic.Int32
			e.startCapture = func(capture.Config) (capture.Session, error) {
				starts.Add(1)
				return nil, errors.New("no real capture in test")
			}
			go func() { defer close(done); e.SelfHeal("power_resume") }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("heal did not reach lookup")
			}
			if action == "stop" {
				if _, err := e.Stop(); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := e.Repair(); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("heal did not finish")
			}
			if starts.Load() != 0 {
				t.Fatal("old self-heal restarted protection after user request")
			}
		})
	}
}

func TestStopDuringHealRestartGapCancelsRestart(t *testing.T) {
	e := New(cleanup.NewRegistry())
	e.state, e.layer = StateActive, layerSelective
	e.protection = true
	e.lookupNet = func(context.Context) netinfo.Info { return netinfo.Info{ASN: "9121", Fingerprint: "test-network"} }
	var starts atomic.Int32
	e.startCapture = func(capture.Config) (capture.Session, error) {
		starts.Add(1)
		return nil, errors.New("no real capture in test")
	}
	e.loadRuleset = func(context.Context) (ruleset.Snapshot, error) { return ruleset.MustLoadEmbedded(), nil }
	stopped, done := make(chan struct{}), make(chan struct{})
	e.cleanup.Register("test", func() error { close(stopped); return nil })
	go func() { defer close(done); e.SelfHeal("power_resume") }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("heal did not stop")
	}
	if st := e.Status(); st.Transition != "network_heal" {
		t.Fatalf("heal cleanup looked like an explicit stop: %+v", st)
	}
	_, _ = e.Stop() // Already stopped is still an explicit request to stay off.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("heal did not finish")
	}
	if starts.Load() != 0 {
		t.Fatal("self-heal ignored stop during restart delay")
	}
	if st := e.Status(); st.Transition != "" || st.Protection {
		t.Fatalf("explicit stop retained automatic reconnection: %+v", st)
	}
}
