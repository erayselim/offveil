package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

type captureWriter struct{ msg *mdns.Msg }

func (w *captureWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *captureWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (w *captureWriter) WriteMsg(m *mdns.Msg) error  { w.msg = m; return nil }
func (w *captureWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *captureWriter) Close() error                { return nil }
func (w *captureWriter) TsigStatus() error           { return nil }
func (w *captureWriter) TsigTimersOnly(bool)         {}
func (w *captureWriter) Hijack()                     {}

func TestIPv4OnlyAnswersAAAAWithoutUpstream(t *testing.T) {
	client := NewDoHClient(nil)
	client.endpoints = nil
	upstream := 0
	client.plainExchange = func(context.Context, *mdns.Msg) (*mdns.Msg, string, error) {
		upstream++
		return nil, "", errors.New("offline")
	}
	stub := NewStub(client, nil)
	stub.SetIPv4Only(true)
	req := new(mdns.Msg)
	req.SetQuestion("blocked.example.", mdns.TypeAAAA)
	w := &captureWriter{}
	stub.handle(w, req)
	if w.msg == nil || w.msg.Rcode != mdns.RcodeSuccess || len(w.msg.Answer) != 0 || w.msg.Id != req.Id || upstream != 0 {
		t.Fatalf("AAAA must be NODATA without upstream: %+v upstream=%d", w.msg, upstream)
	}
	stub.SetIPv4Only(false)
	w = &captureWriter{}
	stub.handle(w, req)
	if w.msg == nil || w.msg.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("AAAA must go upstream when IPv6 is allowed: %+v", w.msg)
	}
}

func TestStripIPv6HintsKeepsOtherParameters(t *testing.T) {
	rr, err := mdns.NewRR(`example.test. 60 IN HTTPS 1 . alpn="h2,h3" ipv4hint="192.0.2.1" ipv6hint="2001:db8::1"`)
	if err != nil {
		t.Fatal(err)
	}
	answer := []mdns.RR{rr}
	stripIPv6Hints(answer)
	text := answer[0].String()
	if strings.Contains(text, "ipv6hint") || !strings.Contains(text, "ipv4hint") || !strings.Contains(text, "alpn") {
		t.Fatalf("hints: %s", text)
	}
}

func TestPoisonWithExtraAndDoHOrder(t *testing.T) {
	set := DefaultPoisonSet().WithExtra([]string{"203.0.113.7", "::1", "bad"})
	if _, ok := set.Match(netip.MustParseAddr("203.0.113.7")); !ok {
		t.Fatal("ruleset fingerprint missing")
	}
	if _, ok := set.Match(netip.MustParseAddr("195.175.254.2")); !ok {
		t.Fatal("built-in fingerprint lost")
	}
	if _, ok := DefaultPoisonSet().Match(netip.MustParseAddr("203.0.113.7")); ok {
		t.Fatal("WithExtra mutated the default set")
	}
	client := NewDoHClient(set)
	if client.PreferredEndpoint() != "https://8.8.8.8/dns-query" || client.Poison() != set {
		t.Fatalf("preferred=%s", client.PreferredEndpoint())
	}
}
