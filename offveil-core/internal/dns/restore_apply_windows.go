//go:build windows

package dns

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// RestoreLeftoverDNS undoes leak-guard DNS using the on-disk snapshot, then
// flushes loopback-only DNS on adapters when no local resolver is listening.
func RestoreLeftoverDNS(armed bool) (detail string, err error) {
	snap, loadErr := LoadRestoreSnapshot()
	if loadErr != nil {
		return "", fmt.Errorf("load snapshot: %w", loadErr)
	}
	restored := 0
	var first error
	if snap != nil {
		armed = true
		for _, nic := range []*RestoreNIC{snap.Tun, snap.Egress} {
			if nic == nil {
				continue
			}
			if e := restoreNIC(*nic); e != nil {
				if first == nil {
					first = e
				}
				continue
			}
			restored++
		}
		_ = ClearRestoreSnapshot()
	}

	flushed, ferr := flushLoopbackDNS(armed)
	if ferr != nil && first == nil {
		first = ferr
	}

	switch {
	case restored > 0 && flushed > 0:
		detail = fmt.Sprintf("restored %d, flushed %d", restored, flushed)
	case restored > 0:
		detail = fmt.Sprintf("restored %d", restored)
	case flushed > 0:
		detail = fmt.Sprintf("flushed %d", flushed)
	default:
		detail = "clean"
	}
	return detail, first
}

func restoreNIC(n RestoreNIC) error {
	if n.LUID == 0 {
		return nil
	}
	luid := winipcfg.LUID(n.LUID)
	addrs := parseIPv4(n.DNS)
	if len(addrs) == 0 {
		return luid.FlushDNS(windows.AF_INET)
	}
	return luid.SetDNS(windows.AF_INET, addrs, nil)
}

func parseIPv4(ss []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			continue
		}
		out = append(out, a)
	}
	return out
}

func flushLoopbackDNS(armed bool) (int, error) {
	if !armed && localResolverListening() {
		return 0, nil
	}
	ifaces, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagDefault)
	if err != nil {
		return 0, err
	}
	flushed := 0
	var first error
	for _, iface := range ifaces {
		if iface.IfType == winipcfg.IfTypeSoftwareLoopback {
			continue
		}
		dns, err := iface.LUID.DNS()
		if err != nil {
			continue
		}
		if !onlyLoopbackIPv4(dns) {
			continue
		}
		if err := iface.LUID.FlushDNS(windows.AF_INET); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		flushed++
	}
	return flushed, first
}

func onlyLoopbackIPv4(addrs []netip.Addr) bool {
	n := 0
	for _, a := range addrs {
		if !a.Is4() {
			continue
		}
		if !a.IsLoopback() {
			return false
		}
		n++
	}
	return n > 0
}

func localResolverListening() bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:53", 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
