//go:build windows

package tunnel

import (
	"context"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestBootstrapWindowsSocketUsesSelectedInterface(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var loopback net.Interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			loopback = iface
			break
		}
	}
	if loopback.Index == 0 {
		t.Fatal("no loopback interface available")
	}
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) {
			address, level := "127.0.0.1:0", windows.IPPROTO_IP
			if family == "tcp6" {
				address, level = "[::1]:0", windows.IPPROTO_IPV6
			}
			listener, err := net.Listen(family, address)
			if err != nil {
				if family == "tcp6" {
					t.Skip("IPv6 loopback unavailable: ", err)
				}
				t.Fatal(err)
			}
			defer listener.Close()
			client := newBootstrapHTTPClient(Config{EgressInterface: loopback.Name})
			defer client.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := client.Transport.(*http.Transport).DialContext(ctx, family, listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			raw, err := conn.(syscall.Conn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var selected int
			var optionErr error
			if err := raw.Control(func(fd uintptr) {
				// Getsockopt returns host order in both address families.
				selected, optionErr = windows.GetsockoptInt(windows.Handle(fd), level, 31)
			}); err != nil {
				t.Fatal(err)
			}
			if optionErr != nil || selected != loopback.Index {
				t.Fatalf("socket not pinned to selected egress: got=%d want=%d err=%v", selected, loopback.Index, optionErr)
			}
		})
	}
}
