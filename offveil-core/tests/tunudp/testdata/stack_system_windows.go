package tun

import (
	"errors"
	"golang.org/x/sys/windows"
)

// Test-only replacement of sing-tun's automatic TCP firewall-rule installer.
// No packet parsing, reassembly, routing or forwarding logic is replaced.
func fixWindowsFirewall() error           { return nil }
func OffveilTestFirewallStubActive() bool { return true }
func retryableListenError(err error) bool { return errors.Is(err, windows.WSAEADDRNOTAVAIL) }
