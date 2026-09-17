package capture

import (
	"net/netip"
	"strings"
)

// DefaultRoute is the IPv4 default-route snapshot (Darwin `route -n get default`).
type DefaultRoute struct {
	Interface string
	Gateway   string
}

// ParseRouteGet reads BSD `route -n get` text.
func ParseRouteGet(out string) DefaultRoute {
	var d DefaultRoute
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "interface":
			d.Interface = val
		case "gateway":
			d.Gateway = val
		}
	}
	return d
}

// OursSplitDefault is true when a leftover 0.0.0.0/1 or 128.0.0.0/1
// belongs to offveil's TUN (10.87.0.1/30), not some other VPN.
func OursSplitDefault(iface, gateway string) bool {
	gw := strings.TrimSpace(gateway)
	if ip, err := netip.ParseAddr(gw); err == nil && ip.Is4() {
		tun, _ := netip.ParsePrefix(TunIPv4)
		if tun.Contains(ip) {
			return true
		}
	}
	return false
}

// PickEgressPrefer prefers the named NIC when it is up, has a gateway, and is
// not virtual. Otherwise falls back to PickEgress.
func PickEgressPrefer(adapters []AdapterInfo, prefer string) *EgressInfo {
	prefer = strings.TrimSpace(prefer)
	if prefer != "" && !IsVirtualDevice(prefer) {
		for i := range adapters {
			a := &adapters[i]
			if a.Name != prefer || a.OperStatus != "up" || a.IsTUNLike {
				continue
			}
			gw := ""
			if len(a.Gateways) > 0 {
				gw = a.Gateways[0]
			}
			return &EgressInfo{
				Name:    a.Name,
				IfIndex: a.IfIndex,
				LUID:    a.LUID,
				Gateway: gw,
				IPv4:    FirstIPv4(a.UnicastAddrs),
			}
		}
	}
	return PickEgress(adapters)
}
