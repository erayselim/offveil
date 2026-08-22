package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
)

// Stub is a local UDP/TCP DNS server that answers via DoH (plain UDP fallback).
type Stub struct {
	client *DoHClient
	poison *PoisonSet
	onQuery QueryObserver

	udpServer *mdns.Server
	tcpServer *mdns.Server

	queries        atomic.Uint64
	fallbacks      atomic.Uint64
	lastPoisonID   atomic.Value // string
	lastPoisonHost atomic.Value // string
}

// NewStub creates a DoH-backed stub (not yet listening).
func NewStub(client *DoHClient, poison *PoisonSet) *Stub {
	if poison == nil {
		poison = DefaultPoisonSet()
	}
	if client == nil {
		client = NewDoHClient(poison)
	}
	s := &Stub{client: client, poison: poison}
	s.lastPoisonID.Store("")
	s.lastPoisonHost.Store("")
	return s
}

// Listen binds UDP+TCP on addr. Caller should then Serve.
func (s *Stub) Listen(addr string) (udp net.PacketConn, tcp net.Listener, err error) {
	udp, err = net.ListenPacket("udp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dns stub udp listen %s: %w", addr, err)
	}
	tcp, err = net.Listen("tcp", addr)
	if err != nil {
		_ = udp.Close()
		return nil, nil, fmt.Errorf("dns stub tcp listen %s: %w", addr, err)
	}
	return udp, tcp, nil
}

// Serve starts UDP+TCP handlers. Blocks until the first server exits.
func (s *Stub) Serve(addr string, udp net.PacketConn, tcp net.Listener) error {
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", s.handle)

	s.udpServer = &mdns.Server{
		Addr:         addr,
		Net:          "udp",
		PacketConn:   udp,
		Handler:      mux,
		UDPSize:      1232,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	s.tcpServer = &mdns.Server{
		Addr:         addr,
		Net:          "tcp",
		Listener:     tcp,
		Handler:      mux,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() { errCh <- s.udpServer.ActivateAndServe() }()
	go func() { errCh <- s.tcpServer.ActivateAndServe() }()
	return <-errCh
}

// Shutdown stops the stub.
func (s *Stub) Shutdown() error {
	var first error
	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(); err != nil && first == nil {
			first = err
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// SetQueryObserver registers a host observer. Safe before Serve.
func (s *Stub) SetQueryObserver(fn QueryObserver) {
	s.onQuery = fn
}

func (s *Stub) handle(w mdns.ResponseWriter, r *mdns.Msg) {
	s.queries.Add(1)
	if len(r.Question) == 0 {
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	if s.onQuery != nil {
		host := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		if host != "" {
			s.onQuery(host)
		}
	}
	msg := new(mdns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.RecursionDesired = true
	if opt := r.IsEdns0(); opt != nil {
		msg.SetEdns0(opt.UDPSize(), opt.Do())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	via := "doh"
	resp, ep, err := s.client.Exchange(ctx, msg)
	if err != nil || resp == nil {
		s.fallbacks.Add(1)
		slog.Debug("dns stub: DoH failed, plain UDP fallback", "q", q.Name, "err", err)
		resp, ep, err = ExchangePlain(ctx, msg, nil)
		via = "plain"
		if err != nil || resp == nil {
			m := new(mdns.Msg)
			m.SetRcode(r, mdns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}
		slog.Debug("dns stub: plain fallback ok", "q", q.Name, "via", ep)
	}

	out := resp.Copy()
	out.Id = r.Id
	out.Response = true
	out.RecursionAvailable = true

	clean, poisonID, poisoned := filterPoisonAnswers(s.poison, out.Answer)
	out.Answer = clean
	if poisoned {
		s.lastPoisonID.Store(poisonID)
		s.lastPoisonHost.Store(mdns.Fqdn(q.Name))
		out.Rcode = mdns.RcodeServerFailure
		out.Answer = nil
		slog.Warn("dns stub: poison answer blocked", "q", q.Name, "id", poisonID, "via", via+":"+ep)
	}
	_ = w.WriteMsg(out)
}

// Stats returns query / poison counters for Info.
func (s *Stub) Stats() (queries uint64, lastID, lastHost string) {
	queries = s.queries.Load()
	if v, ok := s.lastPoisonID.Load().(string); ok {
		lastID = v
	}
	if v, ok := s.lastPoisonHost.Load().(string); ok {
		lastHost = v
	}
	return
}

// FallbackHits is how many queries used plain UDP after DoH failure.
func (s *Stub) FallbackHits() uint64 { return s.fallbacks.Load() }
