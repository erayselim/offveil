package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

// ProbeTLS connects to host:443 through the tunnel SOCKS and classifies the outcome.
func (s *session) ProbeTLS(host string) FailSignal {
	at := time.Now().UTC()
	sig := FailSignal{
		Target:     host,
		ProviderID: string(s.provider),
		At:         at,
	}
	if !s.up.Load() {
		sig.Class = FailDial
		sig.Detail = "tunnel not up"
		s.recordProbe(sig)
		return sig
	}
	if host == "" {
		sig.Class = FailTimeout
		sig.Detail = "empty host"
		s.recordProbe(sig)
		return sig
	}

	timeout := s.cfg.ProbeTimeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Prefer domain CONNECT so sing-box domain_suffix rules match.
	err := tlsViaSOCKS(ctx, s.socks, host, host)
	if err == nil {
		sig.Class = FailOK
		s.recordProbe(sig)
		return sig
	}
	sig.Class = classifyDialErr(err)
	sig.Detail = err.Error()
	s.recordProbe(sig)
	return sig
}

func tlsViaSOCKS(ctx context.Context, socksAddr, dialHost, serverName string) error {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return fmt.Errorf("socks dialer: %w", err)
	}
	type dialerCtx interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}
	target := net.JoinHostPort(dialHost, "443")
	var raw net.Conn
	if dc, ok := d.(dialerCtx); ok {
		raw, err = dc.DialContext(ctx, "tcp", target)
	} else {
		raw, err = d.Dial("tcp", target)
	}
	if err != nil {
		return err
	}
	defer raw.Close()

	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(tlsConn, 1))
	return nil
}

func classifyDialErr(err error) FailClass {
	if err == nil {
		return FailOK
	}
	msg := strings.ToLower(err.Error())
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout") {
		return FailTimeout
	}
	if strings.Contains(msg, "certificate") || strings.Contains(msg, "tls:") || strings.Contains(msg, "x509:") {
		return FailProbe
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNRESET:
			return FailDial
		}
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused") {
		return FailDial
	}
	return FailTimeout
}
