package capture

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// AdapterName is the cosmetic Wintun adapter name (stable GUID via tunnel type).
const (
	AdapterName = "offveil"
	TunnelType  = "offveil"
	TunIPv4     = "10.87.0.1/30"
	DefaultMTU  = 1280
)

// ResolveFunc resolves a hostname to addresses (prefer DoH from internal/dns).
type ResolveFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// Config controls capture bring-up.
type Config struct {
	// Allowlist is optional extra destinations (host or prefix). Never default-route.
	Allowlist []netip.Prefix
	// ResolveHosts are A/AAAA lookup seeds merged into allowlist.
	ResolveHosts []string
	// Resolve overrides system DNS for ResolveHosts (DoH).
	Resolve ResolveFunc
	// ApplyRoutes installs host/prefix routes into the TUN. If false, only adapter+snapshot.
	ApplyRoutes bool
	// SkipAdapter leaves Wintun to sing-box (contracts.md §6.1). Snapshot + resolve only.
	SkipAdapter bool
	MTU         int
}

// DefaultConfig returns capture defaults. Engine fills resolve hosts from the ruleset.
func DefaultConfig() Config {
	hosts := []string{
		"discord.com",
		"gateway.discord.gg",
		"cdn.discordapp.com",
		"media.discordapp.net",
		"discord.gg",
	}
	return Config{
		Allowlist:    nil, // filled by resolve + optional seed
		ResolveHosts: hosts,
		ApplyRoutes:  true,
		MTU:          DefaultMTU,
	}
}

// Snapshot is a multi-adapter fail-safe picture taken before mutating routes.
type Snapshot struct {
	TakenAt  time.Time     `json:"taken_at"`
	Egress   *EgressInfo   `json:"egress,omitempty"`
	Adapters []AdapterInfo `json:"adapters"`
}

// AdapterInfo describes one NIC at snapshot time.
type AdapterInfo struct {
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	IfIndex      uint32   `json:"if_index"`
	LUID         uint64   `json:"luid"`
	OperStatus   string   `json:"oper_status"`
	IPv4Metric   uint32   `json:"ipv4_metric,omitempty"`
	Gateways     []string `json:"gateways,omitempty"`
	UnicastAddrs []string `json:"unicast,omitempty"`
	IsTUNLike    bool     `json:"is_tun_like,omitempty"`
}

// EgressInfo is the physical NIC used for loop-prevention bind later (ciadpi --conn-ip).
type EgressInfo struct {
	Name    string `json:"name"`
	IfIndex uint32 `json:"if_index"`
	LUID    uint64 `json:"luid"`
	Gateway string `json:"gateway,omitempty"`
	IPv4    string `json:"ipv4,omitempty"`
}

// Info is runtime capture status surfaced via engine/status.
type Info struct {
	AdapterName   string      `json:"adapter_name"`
	LUID          uint64      `json:"luid,omitempty"`
	IPv4          string      `json:"ipv4,omitempty"`
	MTU           int         `json:"mtu,omitempty"`
	RoutesApplied int         `json:"routes_applied"`
	RoutePrefixes []string    `json:"route_prefixes,omitempty"`
	Egress        *EgressInfo `json:"egress,omitempty"`
	WintunVersion string      `json:"wintun_version,omitempty"`
	DLLPath       string      `json:"dll_path,omitempty"`
	Snapshot      *Snapshot   `json:"snapshot,omitempty"`
}

// Session is an active capture stack (adapter + optional selected routes).
type Session interface {
	Info() Info
	Close() error
	// AddPrefixes installs extra destination prefixes (domain expand).
	// Already-present prefixes are skipped. Returns how many were newly added.
	AddPrefixes(prefixes []netip.Prefix) (added int, err error)
	// AttachAdapter binds to an existing Wintun (sing-box TUN) by friendly name
	// so later AddPrefixes can install extra /32s. No-op if this session owns the adapter.
	AttachAdapter(name string) error
}

// ResolveHostsToPrefixes looks up A records and returns /32 prefixes (IPv4).
// If resolve is nil, falls back to net.LookupIP (system DNS - avoid in production).
// Lookups run in parallel; overall budget is 12s so a hung resolver cannot stall engine start.
func ResolveHostsToPrefixes(hosts []string, resolve ResolveFunc) ([]netip.Prefix, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	var firstErr error
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	type one struct {
		addrs []netip.Addr
		err   error
	}
	ch := make(chan one, len(hosts))
	var wg sync.WaitGroup
	for _, h := range hosts {
		h := h
		wg.Add(1)
		go func() {
			defer wg.Done()
			var addrs []netip.Addr
			var err error
			if resolve != nil {
				addrs, err = resolve(ctx, h)
			} else {
				addrs, err = systemLookupA(h)
			}
			ch <- one{addrs: addrs, err: err}
		}()
	}
	go func() {
		wg.Wait()
		close(ch)
	}()

	var out []netip.Prefix
	for r := range ch {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		for _, addr := range r.addrs {
			if !addr.Is4() {
				continue
			}
			out = append(out, netip.PrefixFrom(addr, 32))
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func systemLookupA(host string) ([]netip.Addr, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.To4())
		if ok {
			out = append(out, addr)
		}
	}
	return out, nil
}

// BuildAllowlist merges static + resolved hosts and applies exclude filter.
func BuildAllowlist(cfg Config) ([]netip.Prefix, error) {
	merged := append([]netip.Prefix{}, cfg.Allowlist...)
	if len(cfg.ResolveHosts) > 0 {
		resolved, err := ResolveHostsToPrefixes(cfg.ResolveHosts, cfg.Resolve)
		if err != nil && len(merged) == 0 {
			return nil, err
		}
		merged = append(merged, resolved...)
	}
	return FilterAllowlist(merged, DefaultExcludePrefixes()), nil
}
