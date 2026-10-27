package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// Provider orchestration must work even while the active remote dataplane is
// broken. Resolve outside that dataplane and bind sockets to its physical
// egress; a source address alone does not constrain route selection on every OS.
func newBootstrapHTTPClient(cfg Config) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if cfg.EgressInterface != "" {
		dialer.Control = func(network, _ string, raw syscall.RawConn) error {
			iface, err := net.InterfaceByName(cfg.EgressInterface)
			if err != nil {
				return fmt.Errorf("bootstrap interface: %w", err)
			}
			var bindErr error
			if err := raw.Control(func(fd uintptr) {
				bindErr = bindBootstrapSocket(fd, network, iface.Index)
			}); err != nil {
				return err
			}
			return bindErr
		}
	}
	transport := &http.Transport{
		// Do not inherit environment proxies or a transport routed via TUN.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if _, err := netip.ParseAddr(host); err != nil && cfg.Resolve != nil {
				addr, err := cfg.Resolve(ctx, host)
				if err != nil {
					return nil, fmt.Errorf("bootstrap DNS: %w", err)
				}
				if !addr.IsValid() || addr.IsUnspecified() {
					return nil, fmt.Errorf("bootstrap DNS returned no address")
				}
				address = net.JoinHostPort(addr.String(), port)
			}
			return dialer.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		IdleConnTimeout:       10 * time.Second,
		MaxIdleConns:          2,
	}
	// Transport retains the URL hostname for TLS/SNI and verifies certificates
	// normally even though DialContext connects to the resolved literal address.
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}
}
