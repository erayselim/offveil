//go:build windows

package capture

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// installedRoute tracks a selected-route prefix for teardown.
type installedRoute struct {
	dst netip.Prefix
}

func setTunIPv4(luid uint64, prefix netip.Prefix, mtu int) error {
	if !prefix.Addr().Is4() {
		return fmt.Errorf("only IPv4 TUN address supported")
	}
	l := winipcfg.LUID(luid)
	if err := l.AddIPAddress(prefix); err != nil {
		return fmt.Errorf("AddIPAddress: %w", err)
	}

	iface, err := l.IPInterface(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("IPInterface: %w", err)
	}
	iface.UseAutomaticMetric = false
	iface.Metric = 5
	iface.DadTransmits = 0
	iface.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	if mtu > 0 {
		iface.NLMTU = uint32(mtu)
	}
	if err := iface.Set(); err != nil {
		return fmt.Errorf("Set IP interface: %w", err)
	}
	return nil
}

func clearTunIPv4(luid uint64, prefix netip.Prefix) error {
	err := winipcfg.LUID(luid).DeleteIPAddress(prefix)
	if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return err
	}
	return nil
}

func addSelectedRoute(luid uint64, dst netip.Prefix) (installedRoute, error) {
	l := winipcfg.LUID(luid)
	err := l.AddRoute(dst.Masked(), netip.IPv4Unspecified(), 1)
	if err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return installedRoute{dst: dst}, nil
		}
		return installedRoute{}, fmt.Errorf("AddRoute %s: %w", dst, err)
	}
	return installedRoute{dst: dst}, nil
}

func deleteSelectedRoute(luid uint64, ir installedRoute) error {
	err := winipcfg.LUID(luid).DeleteRoute(ir.dst.Masked(), netip.IPv4Unspecified())
	if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return err
	}
	return nil
}
