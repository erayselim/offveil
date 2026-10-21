package engine_test

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/engine"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
)

type captureRouteCounter struct {
	*capture.FakeSession
	calls int
}

func (c *captureRouteCounter) AddPrefixes(prefixes []netip.Prefix) (int, error) {
	c.calls++
	return c.FakeSession.AddPrefixes(prefixes)
}

func TestDNSObservationsDoNotProbeOrChangeCapture(t *testing.T) {
	capSession := &captureRouteCounter{FakeSession: capture.NewFakeSession(capture.Info{})}
	probeCalls := 0
	eng := newTestEngine(t).
		WithCaptureStart(func(capture.Config) (capture.Session, error) { return capSession, nil }).
		WithProbe(func(context.Context, *offdns.DoHClient, []string) probe.Report { probeCalls++; return probe.Report{} })
	if _, rpcErr := eng.Start("auto"); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	before := eng.Status()
	for _, host := range []string{"Requested.Example.Test.", "requested.example.test", "opaque.service.test", "cdn.unrelated.test", "1.2.3.4.in-addr.arpa", "printer.local", "https://invalid.test", "bad..test"} {
		eng.HandleExpandQueryForTest(host)
	}
	after := eng.Status()
	observations, ok := after.Expand.(*engine.ExpandInfo)
	if !ok || observations.HostsSeen != 3 {
		t.Fatalf("actual DNS demand: %+v", after.Expand)
	}
	if observations.RoutesAdded != 0 || capSession.calls != 0 || probeCalls != 0 {
		t.Fatalf("DNS observation changed routing or probed: observation=%+v routeCalls=%d probeCalls=%d", observations, capSession.calls, probeCalls)
	}
	if after.State != before.State || after.OutboundHint != before.OutboundHint || !reflect.DeepEqual(after.Targets, before.Targets) {
		t.Fatal("an observed destination changed network status")
	}
}

func TestDNSObservationMemoryIsBounded(t *testing.T) {
	eng := newTestEngine(t)
	if _, rpcErr := eng.Start("auto"); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	for i := range 256 {
		eng.HandleExpandQueryForTest(fmt.Sprintf("host-%d.example.test", i))
	}
	info, ok := eng.Status().Expand.(*engine.ExpandInfo)
	if !ok || info.HostsSeen != 128 || info.RoutesAdded != 0 {
		t.Fatalf("unbounded or speculative observation: %+v", eng.Status().Expand)
	}
}

func TestStartReportsOnlyNetworkTransportTargets(t *testing.T) {
	eng := newTestEngine(t)
	st, rpcErr := eng.Start("auto")
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	requireNetworkTargets(t, st, "tunnel", "tunnel")
	if len(st.Targets) != 2 {
		t.Fatalf("unexpected destination-specific targets: %+v", st.Targets)
	}
}
