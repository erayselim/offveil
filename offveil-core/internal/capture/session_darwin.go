//go:build darwin

package capture

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type session struct {
	mu          sync.Mutex
	snapshot    *Snapshot
	allowlist   []netip.Prefix
	mtu         int
	tunPrefix   netip.Prefix
	skipAdapter bool
	closing     atomic.Bool
}

var runRouteGet = func(args ...string) (string, error) {
	cmd := exec.Command("/sbin/route", args...)
	b, err := cmd.CombinedOutput()
	return string(b), err
}

// Start snapshots the egress NIC. Darwin never owns the TUN: sing-box opens
// utun (SkipAdapter). Wintun / CloseOrphanAdapter do not exist.
func Start(cfg Config) (Session, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("privilege: TUN requires root")
	}
	cfg.SkipAdapter = true
	cfg.ApplyRoutes = false

	snap, err := TakeSnapshot()
	if err != nil {
		return nil, fmt.Errorf("adapter snapshot: %w", err)
	}
	if snap.Egress == nil {
		return nil, fmt.Errorf("no usable egress NIC (Wi-Fi/Ethernet with gateway)")
	}
	slog.Info("capture: egress selected",
		"name", snap.Egress.Name,
		"ifIndex", snap.Egress.IfIndex,
		"gateway", snap.Egress.Gateway,
		"adapters", len(snap.Adapters),
	)

	slog.Info("capture: resolving allowlist", "hosts", len(cfg.ResolveHosts), "skip_adapter", true)
	allow, err := BuildAllowlist(cfg)
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	s := &session{
		snapshot:    snap,
		allowlist:   allow,
		mtu:         mtu,
		tunPrefix:   netip.MustParsePrefix(TunIPv4),
		skipAdapter: true,
	}
	slog.Info("capture: snapshot-only (sing-box owns utun)", "routes_planned", len(allow))
	return s, nil
}

func (s *session) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefixes := make([]string, 0, len(s.allowlist))
	for _, p := range s.allowlist {
		prefixes = append(prefixes, p.String())
	}
	var eg *EgressInfo
	if s.snapshot != nil {
		eg = s.snapshot.Egress
	}
	return Info{
		AdapterName:   AdapterName,
		IPv4:          s.tunPrefix.String(),
		MTU:           s.mtu,
		RoutesApplied: len(prefixes),
		RoutePrefixes: prefixes,
		Egress:        eg,
		WintunVersion: "sing-box",
	}
}

func (s *session) Close() error {
	if !s.closing.CompareAndSwap(false, true) {
		return nil
	}
	slog.Info("capture: snapshot session down (dataplane adapter owned by sing-box)")
	return nil
}

func (s *session) AddPrefixes([]netip.Prefix) (int, error) {
	// Split-default auto_route already captures public IPv4. No extra /32s.
	return 0, nil
}

func (s *session) AttachAdapter(string) error {
	return nil
}

// TakeSnapshot lists NICs and picks the default-route egress (not utun).
func TakeSnapshot() (*Snapshot, error) {
	adapters, err := listAdapters()
	if err != nil {
		return nil, err
	}
	dr := lookupDefaultRoute()
	if dr.Interface != "" {
		for i := range adapters {
			if adapters[i].Name != dr.Interface {
				continue
			}
			if dr.Gateway != "" && len(adapters[i].Gateways) == 0 {
				adapters[i].Gateways = []string{dr.Gateway}
			}
			if !adapters[i].IsTUNLike {
				adapters[i].IPv4Metric = 1
			}
		}
	}
	return &Snapshot{
		TakenAt:  time.Now().UTC(),
		Adapters: adapters,
		Egress:   PickEgressPrefer(adapters, dr.Interface),
	}, nil
}

func lookupDefaultRoute() DefaultRoute {
	out, err := runRouteGet("-n", "get", "default")
	if err != nil {
		slog.Warn("capture: route get default", "err", err)
		return DefaultRoute{}
	}
	return ParseRouteGet(out)
}

func listAdapters() ([]AdapterInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]AdapterInfo, 0, len(ifaces))
	for _, ifi := range ifaces {
		info := AdapterInfo{
			Name:       ifi.Name,
			IfIndex:    uint32(ifi.Index),
			OperStatus: "down",
			IsTUNLike:  IsVirtualDevice(ifi.Name),
			IPv4Metric: 50,
		}
		if ifi.Flags&net.FlagUp != 0 {
			info.OperStatus = "up"
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			out = append(out, info)
			continue
		}
		for _, a := range addrs {
			ip := addrIP(a)
			if ip == "" {
				continue
			}
			info.UnicastAddrs = append(info.UnicastAddrs, ip)
		}
		out = append(out, info)
	}
	return out, nil
}

func addrIP(a net.Addr) string {
	switch v := a.(type) {
	case *net.IPNet:
		if v.IP == nil || v.IP.To4() == nil {
			return ""
		}
		return v.IP.To4().String()
	case *net.IPAddr:
		if v.IP == nil || v.IP.To4() == nil {
			return ""
		}
		return v.IP.To4().String()
	default:
		s := a.String()
		host, _, ok := strings.Cut(s, "/")
		if ok {
			s = host
		}
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() {
			return ""
		}
		return ip.String()
	}
}

// FindAdapterLUIDByName is a Windows Wintun hook. Darwin has no LUID.
func FindAdapterLUIDByName(string) (uint64, error) {
	return 0, fmt.Errorf("capture: adapter LUID is Windows-only")
}
