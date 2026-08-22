package dns

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

// session is the live DoH stub + optional Windows DNS leak guard.
type session struct {
	mu sync.Mutex

	cfg    Config
	client *DoHClient
	stub   *Stub
	guard  *leakGuard
	nrpt   *nrptGuard
	listen string

	serving atomic.Bool
	errCh   chan error
}

// Start brings up the local DoH stub and optional leak guard.
func Start(cfg Config) (Session, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:53"
	}
	poison := DefaultPoisonSet()
	client := NewDoHClient(poison)
	stub := NewStub(client, poison)
	if cfg.OnQuery != nil {
		stub.SetQueryObserver(cfg.OnQuery)
	}

	udp, tcp, err := stub.Listen(cfg.ListenAddr)
	if err != nil {
		return nil, err
	}

	s := &session{
		cfg:    cfg,
		client: client,
		stub:   stub,
		listen: cfg.ListenAddr,
		errCh:  make(chan error, 1),
	}

	s.serving.Store(true)
	go func() {
		err := stub.Serve(cfg.ListenAddr, udp, tcp)
		s.serving.Store(false)
		if err != nil {
			select {
			case s.errCh <- err:
			default:
			}
		}
	}()

	if cfg.ApplyLeakGuard {
		if cfg.TunLUID == 0 {
			_ = s.Close()
			return nil, fmt.Errorf("dns leak guard requires TunLUID")
		}
		g, err := newLeakGuard(cfg.ListenAddr, cfg.TunLUID, cfg.EgressLUID)
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		if err := g.Apply(); err != nil {
			_ = s.Close()
			return nil, err
		}
		s.guard = g
		slog.Info("dns: leak guard applied",
			"stub", cfg.ListenAddr,
			"tun", cfg.TunLUID,
			"egress", cfg.EgressLUID,
		)
	}

	if len(cfg.NRPTSuffixes) > 0 {
		n, err := newNRPTGuard(cfg.ListenAddr, cfg.NRPTSuffixes)
		if err != nil {
			slog.Warn("dns: NRPT apply failed (stub still up; ISP DNS may poison allowlist)", "err", err)
		} else {
			s.nrpt = n
		}
	}

	slog.Info("dns: stub up", "listen", cfg.ListenAddr, "doh", client.endpoints, "nrpt", s.nrpt != nil)
	return s, nil
}

func splitHostPortDefault(addr, defaultPort string) (host, port string, err error) {
	if addr == "" {
		return "", "", fmt.Errorf("empty address")
	}
	if !strings.Contains(addr, ":") {
		return addr, defaultPort, nil
	}
	// Handle bare IPv6 in brackets via net.SplitHostPort.
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	return h, p, nil
}

func (s *session) Client() *DoHClient { return s.client }

func (s *session) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, lastID, lastHost := s.stub.Stats()
	return Info{
		ListenAddr:     s.listen,
		DoHEndpoints:   append([]string{}, s.client.endpoints...),
		StubUp:         s.serving.Load(),
		LeakGuard:      s.guard != nil,
		NRPT:           s.nrpt != nil && s.nrpt.applied,
		PoisonHits:     s.client.PoisonHits(),
		Queries:        q,
		PlainFallbacks: s.stub.FallbackHits(),
		DoHMode:        s.client.Mode(),
		LastPoisonID:   lastID,
		LastPoisonHost: lastHost,
	}
}

func (s *session) Close() error {
	s.mu.Lock()
	guard := s.guard
	s.guard = nil
	nrpt := s.nrpt
	s.nrpt = nil
	stub := s.stub
	s.mu.Unlock()

	var first error
	if nrpt != nil {
		if err := nrpt.Close(); err != nil && first == nil {
			first = err
		}
	}
	if guard != nil {
		if err := guard.Close(); err != nil && first == nil {
			first = err
		}
	}
	if stub != nil {
		if err := stub.Shutdown(); err != nil && first == nil {
			first = err
		}
	}
	slog.Info("dns: stub down")
	return first
}

// FakeSession is an in-memory Session for unit tests.
type FakeSession struct {
	info   Info
	client *DoHClient
	closed bool
}

// NewFakeSession returns a no-op DNS session.
func NewFakeSession(info Info) *FakeSession {
	if info.ListenAddr == "" {
		info.ListenAddr = "127.0.0.1:53"
	}
	info.StubUp = true
	return &FakeSession{info: info, client: NewDoHClient(DefaultPoisonSet())}
}

func (f *FakeSession) Info() Info         { return f.info }
func (f *FakeSession) Client() *DoHClient { return f.client }
func (f *FakeSession) Close() error {
	f.closed = true
	f.info.StubUp = false
	return nil
}
