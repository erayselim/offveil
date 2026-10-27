package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
)

func TestRelayASNChangeDoesNotRebindPhysicalNetwork(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	e := activeBackgroundEngine(t)
	e.lookupNet = func(context.Context) netinfo.Info {
		return netinfo.Info{ASN: "13335", Fingerprint: "network-a"}
	}
	var starts atomic.Int32
	e.startCapture = func(capture.Config) (capture.Session, error) {
		starts.Add(1)
		return nil, errors.New("unexpected physical rebind")
	}
	e.SelfHeal("network_change")
	if starts.Load() != 0 || !e.Status().Protection || e.policy.ASN() != "13335" {
		t.Fatal("relay ASN metadata restarted a physically unchanged network")
	}
	// TTL identity refresh may still invalidate learned paths, without binding
	// the physical stack to whichever relay happened to answer public-IP HTTP.
	e.lookupNet = func(context.Context) netinfo.Info {
		return netinfo.Info{ASN: "9121", Fingerprint: "network-a"}
	}
	e.silentReprobe()
	if starts.Load() != 0 || !e.Status().Protection || e.policy.ASN() != "9121" {
		t.Fatal("metadata refresh lost the physical network")
	}
}

func TestHealPublishesReconnectingDuringBlockedRestart(t *testing.T) {
	e := startedNetworkFixture(t, func(offdns.Config) (offdns.Session, error) {
		return offdns.NewFakeSession(offdns.Info{}), nil
	})
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.startCapture = func(capture.Config) (capture.Session, error) {
		close(entered)
		<-release
		return capture.NewFakeSession(capture.Info{}), nil
	}
	go func() { defer close(done); e.SelfHeal("power_resume") }()
	finish := sync.OnceFunc(func() { close(release); <-done })
	defer finish()
	awaitBackground(t, entered)
	if st := e.Status(); st.State != StateStarting || st.Protection || st.Transition != "network_heal" {
		t.Fatalf("published startup snapshot lost automatic reconnect: %+v", st)
	}
	finish()
	if st := e.Status(); !st.Protection || st.Transition != "" {
		t.Fatalf("completed heal retained transitional UI state: %+v", st)
	}
}
