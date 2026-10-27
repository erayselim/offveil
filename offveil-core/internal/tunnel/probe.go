package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	parent := s.cfg.Context
	if parent == nil {
		parent = context.Background()
	}
	sig := s.probeTLSContext(parent, host)
	s.recordProbe(sig)
	return sig
}

func (s *session) probeTLSContext(parent context.Context, host string) FailSignal {
	at := time.Now().UTC()
	sig := FailSignal{
		Target:     host,
		ProviderID: string(s.provider),
		At:         at,
	}
	if !s.isUp() {
		sig.Class = FailDial
		sig.Detail = "tunnel not up"
		return sig
	}
	if host == "" {
		sig.Class = FailConfig
		sig.Detail = "empty host"
		return sig
	}

	timeout := s.cfg.ProbeTimeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	// Tunnel providers need the domain for selective routing. The local
	// ByeDPI helper rejects domain CONNECT (--no-domain), so its dataplane
	// check must use the same resolved-IP destination as TUN traffic.
	dialHost := host
	if (s.provider == ProviderDesync || s.cfg.Selective && !s.cfg.providerOnly) && s.cfg.Resolve != nil {
		addr, err := s.cfg.Resolve(ctx, host)
		if err != nil {
			sig.Class, sig.Detail = classifyDialErr(err), "resolve: "+err.Error()
			return sig
		}
		dialHost = addr.String()
	}
	err := tlsViaSOCKS(ctx, s.socks, dialHost, host)
	if err == nil {
		sig.Class = FailOK
		return sig
	}
	sig.Class = classifyDialErr(err)
	sig.Detail = err.Error()
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

	return tlsHandshake(ctx, raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	})
}

func tlsHandshake(ctx context.Context, raw net.Conn, cfg *tls.Config) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			return err
		}
	}
	// HTTPS servers wait for a request after TLS; unsolicited application data
	// is not a liveness signal. Certificate-verified TLS is the probe boundary.
	return tls.Client(raw, cfg).HandshakeContext(ctx)
}

func classifyDialErr(err error) FailClass {
	if err == nil {
		return FailOK
	}
	msg := strings.ToLower(err.Error())
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout") {
		return FailTimeout
	}
	var certificate *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	if errors.As(err, &certificate) || errors.As(err, &authority) || errors.As(err, &hostname) || strings.Contains(msg, "certificate") || strings.Contains(msg, "x509:") {
		return FailCertificate
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(msg, "unexpected eof") {
		return FailEOF
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNRESET:
			return FailReset
		case syscall.ECONNREFUSED:
			return FailRefused
		}
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused") {
		return FailRefused
	}
	if strings.Contains(msg, "connection reset") || strings.Contains(msg, "forcibly closed") {
		return FailReset
	}
	if strings.Contains(msg, "tls:") {
		return FailProbe
	}
	return FailDial
}
