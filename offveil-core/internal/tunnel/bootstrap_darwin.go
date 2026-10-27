//go:build darwin

package tunnel

import "golang.org/x/sys/unix"

func bindBootstrapSocket(fd uintptr, network string, index int) error {
	if network == "tcp6" || network == "udp6" {
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
	}
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
}
