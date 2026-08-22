//go:build windows

package dns

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// leakGuard snapshots and rewrites interface DNS so queries hit the local stub.
type leakGuard struct {
	stubIP     netip.Addr
	tunLUID    winipcfg.LUID
	egressLUID winipcfg.LUID

	prevTun    []netip.Addr
	prevEgress []netip.Addr
	haveTun    bool
	haveEgress bool
	applied    bool
}

func newLeakGuard(stubHost string, tunLUID, egressLUID uint64) (*leakGuard, error) {
	host, _, err := splitHostPortDefault(stubHost, "53")
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("stub IP: %w", err)
	}
	if !ip.IsLoopback() && !ip.IsPrivate() {
		return nil, fmt.Errorf("stub DNS must be loopback or private, got %s", ip)
	}
	return &leakGuard{
		stubIP:     ip,
		tunLUID:    winipcfg.LUID(tunLUID),
		egressLUID: winipcfg.LUID(egressLUID),
	}, nil
}

func (g *leakGuard) Apply() error {
	if g.tunLUID != 0 {
		prev, err := g.tunLUID.DNS()
		if err == nil {
			g.prevTun = filterFamily(prev, true)
			g.haveTun = true
		}
	}
	if g.egressLUID != 0 {
		prev, err := g.egressLUID.DNS()
		if err == nil {
			g.prevEgress = filterFamily(prev, true)
			g.haveEgress = true
		}
	}
	_ = SaveRestoreSnapshot(g.snapshot())

	if g.tunLUID != 0 {
		if err := g.tunLUID.SetDNS(windows.AF_INET, []netip.Addr{g.stubIP}, nil); err != nil {
			_ = g.restoreTun()
			_ = ClearRestoreSnapshot()
			return fmt.Errorf("set TUN DNS: %w", err)
		}
	}
	if g.egressLUID != 0 {
		if err := g.egressLUID.SetDNS(windows.AF_INET, []netip.Addr{g.stubIP}, nil); err != nil {
			_ = g.restoreTun()
			_ = ClearRestoreSnapshot()
			return fmt.Errorf("set egress DNS: %w", err)
		}
	}
	g.applied = true
	return nil
}

func (g *leakGuard) snapshot() RestoreSnapshot {
	snap := RestoreSnapshot{StubIP: g.stubIP.String()}
	if g.haveTun {
		snap.Tun = &RestoreNIC{LUID: uint64(g.tunLUID), DNS: addrsToStrings(g.prevTun)}
	}
	if g.haveEgress {
		snap.Egress = &RestoreNIC{LUID: uint64(g.egressLUID), DNS: addrsToStrings(g.prevEgress)}
	}
	return snap
}

func (g *leakGuard) Close() error {
	if !g.applied {
		return nil
	}
	var first error
	if err := g.restoreEgress(); err != nil && first == nil {
		first = err
	}
	if err := g.restoreTun(); err != nil && first == nil {
		first = err
	}
	g.applied = false
	if first == nil {
		_ = ClearRestoreSnapshot()
	}
	return first
}

func addrsToStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func (g *leakGuard) restoreTun() error {
	if g.tunLUID == 0 || !g.haveTun {
		if g.tunLUID != 0 {
			return g.tunLUID.FlushDNS(windows.AF_INET)
		}
		return nil
	}
	return g.tunLUID.SetDNS(windows.AF_INET, g.prevTun, nil)
}

func (g *leakGuard) restoreEgress() error {
	if g.egressLUID == 0 || !g.haveEgress {
		return nil
	}
	return g.egressLUID.SetDNS(windows.AF_INET, g.prevEgress, nil)
}

func filterFamily(addrs []netip.Addr, v4 bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if v4 && a.Is4() {
			out = append(out, a)
		}
		if !v4 && a.Is6() {
			out = append(out, a)
		}
	}
	return out
}
