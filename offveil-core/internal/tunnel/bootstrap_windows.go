//go:build windows

package tunnel

import (
	"encoding/binary"

	"golang.org/x/sys/windows"
)

func bindBootstrapSocket(fd uintptr, network string, index int) error {
	const unicastIF = 31 // IP_UNICAST_IF / IPV6_UNICAST_IF
	if network == "tcp6" || network == "udp6" {
		return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, unicastIF, index)
	}
	// Winsock takes the IPv4 interface index in network byte order; IPv6 uses
	// host order. See Microsoft's IPPROTO_IP / IPPROTO_IPV6 socket options.
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(index))
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, unicastIF, int(binary.NativeEndian.Uint32(encoded[:])))
}
