package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Observe the SOCKS request and ClientHello on an owned loopback listener.
// ByeDPI --no-domain accepts an IP destination, while TLS still needs the SNI.
func TestDesyncDataplaneProbeUsesResolvedIPAndOriginalSNI(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	destination := make(chan netip.Addr, 1)
	sni := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		greeting := make([]byte, 3)
		if _, err = io.ReadFull(conn, greeting); err != nil {
			done <- err
			return
		}
		if _, err = conn.Write([]byte{5, 0}); err != nil {
			done <- err
			return
		}
		header := make([]byte, 4)
		if _, err = io.ReadFull(conn, header); err != nil {
			done <- err
			return
		}
		if header[3] != 1 {
			done <- errors.New("SOCKS destination must be IPv4, not a domain")
			return
		}
		address := make([]byte, 6)
		if _, err = io.ReadFull(conn, address); err != nil {
			done <- err
			return
		}
		destination <- netip.AddrFrom4([4]byte{address[0], address[1], address[2], address[3]})
		if _, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
			done <- err
			return
		}
		server := tls.Server(conn, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni <- hello.ServerName
			return nil, errors.New("synthetic TLS rejection; no trusted test certificate needed")
		}})
		_ = server.Handshake()
		done <- nil
	}()
	s := &session{provider: ProviderDesync, socks: ln.Addr().String(), cfg: Config{
		ProbeTimeout: time.Second,
		Resolve:      func(context.Context, string) (netip.Addr, error) { return netip.MustParseAddr("192.0.2.10"), nil },
	}}
	s.up.Store(true)
	sig := s.ProbeTLS("secure.imvu.com")
	if sig.Class == FailOK {
		t.Fatal("rejected TLS certificate/handshake reported healthy")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("SOCKS probe did not finish: %+v", sig)
	}
	select {
	case got := <-destination:
		if got.String() != "192.0.2.10" {
			t.Fatalf("destination=%s", got)
		}
	default:
		t.Fatal("SOCKS destination not observed")
	}
	select {
	case got := <-sni:
		if got != "secure.imvu.com" {
			t.Fatalf("SNI=%s", got)
		}
	default:
		t.Fatal("TLS SNI not observed")
	}
}
