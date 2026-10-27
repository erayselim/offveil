package netinfo

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
)

type sourceConn struct {
	net.Conn
	ip net.IP
}

func (c sourceConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: c.ip} }
func (c sourceConn) Close() error        { return nil }

func TestLocalFingerprintIgnoresOwnedTUNRoutes(t *testing.T) {
	for _, dualStack := range []bool{false, true} {
		physical4 := "192.168.1.10"
		fingerprint := func(tun bool) string {
			return fingerprintIPs(discoverLocalIPsWith(func(network, address string, _ time.Duration) (net.Conn, error) {
				if network != "udp" {
					t.Fatalf("fingerprinting sends traffic: %s", network)
				}
				peer := netip.MustParseAddrPort(address).Addr()
				// Emulate split-default capture on an IPv4-only or dual-stack LAN.
				if tun && !capture.IsExcluded(peer, capture.DefaultExcludePrefixes()) {
					return sourceConn{ip: net.ParseIP(netip.MustParsePrefix(capture.TunIPv6).Addr().String())}, nil
				}
				if peer.Is4() {
					return sourceConn{ip: net.ParseIP(physical4)}, nil
				}
				if dualStack {
					return sourceConn{ip: net.ParseIP("2001:db8:1234::2")}, nil
				}
				return nil, errors.New("no physical IPv6 route")
			}))
		}
		before := fingerprint(false)
		if after := fingerprint(true); before != after {
			t.Errorf("dual_stack=%t: own TUN changed physical identity: %s -> %s", dualStack, before, after)
		}
		physical4 = "192.168.2.10"
		if fingerprint(true) == before {
			t.Error("physical DHCP/network change was hidden")
		}
	}
}
