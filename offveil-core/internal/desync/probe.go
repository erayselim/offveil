package desync

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

// ProbeTLS connects to host:443 through the desync SOCKS and classifies the outcome.
// Classification mirrors ByeDPI --auto triggers: torst → timeout|reset, ssl_err, ok.
func (s *session) ProbeTLS(host string) FailSignal {
	at := time.Now().UTC()
	sig := FailSignal{
		Target:     host,
		StrategyID: s.strategy.ID,
		At:         at,
	}
	if host == "" {
		sig.Class = FailTimeout
		sig.Detail = "empty host"
		s.recordProbe(sig)
		return sig
	}

	timeout := s.cfg.ProbeTimeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialHost := host
	if s.cfg.Resolve != nil {
		addr, rerr := s.cfg.Resolve(ctx, host)
		if rerr != nil {
			sig.Class = FailTimeout
			sig.Detail = "resolve: " + rerr.Error()
			s.recordProbe(sig)
			return sig
		}
		dialHost = addr.String()
	}

	err := tlsViaSOCKS(ctx, s.socks, dialHost, host)
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

// tlsViaSOCKS dials dialHost:443 via SOCKS; TLS SNI uses serverName (may differ when dialHost is an IP).
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

	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}

	cfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	_ = tc.Close()
	return nil
}

// classifyDialErr maps net/tls errors to FailClass for policy.
func classifyDialErr(err error) FailClass {
	if err == nil {
		return FailOK
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return FailTimeout
	}

	var op *net.OpError
	if errors.As(err, &op) {
		if op.Timeout() {
			return FailTimeout
		}
		if errors.Is(op.Err, syscall.ECONNRESET) || errors.Is(op.Err, syscall.ECONNABORTED) {
			return FailReset
		}
		msg := strings.ToLower(op.Err.Error())
		if strings.Contains(msg, "forcibly closed") ||
			strings.Contains(msg, "connection reset") ||
			strings.Contains(msg, "wsarecv") {
			return FailReset
		}
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "deadline exceeded"),
		strings.Contains(msg, "timed out"):
		return FailTimeout
	case strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "forcibly closed"),
		strings.Contains(msg, "broken pipe"):
		return FailReset
	case strings.Contains(msg, "tls:"),
		strings.Contains(msg, "handshake"),
		strings.Contains(msg, "certificate"),
		strings.Contains(msg, "first record"),
		strings.Contains(msg, "server hello"):
		return FailSSLErr
	}

	var te interface{ Timeout() bool }
	if errors.As(err, &te) && te.Timeout() {
		return FailTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		// Early close after ClientHello ≈ DPI reset (ByeDPI torst).
		return FailReset
	}
	// Unknown transport failure → timeout for cascade (desync → tunnel).
	return FailTimeout
}

// ReportFail notifies the configured Sink (and updates counters).
func (s *session) ReportFail(target string, class FailClass, detail string) {
	sig := FailSignal{
		Target:     target,
		Class:      class,
		StrategyID: s.strategy.ID,
		Detail:     detail,
		At:         time.Now().UTC(),
	}
	s.recordProbe(sig)
	if s.cfg.Sink != nil && class != FailOK {
		s.cfg.Sink.OnDesyncFail(sig)
	}
}
