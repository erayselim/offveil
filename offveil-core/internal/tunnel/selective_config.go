package tunnel

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/erayselim/offveil/offveil-core/internal/udp"
)

// Group paths. TCP of a group follows desync or tunnel; its UDP follows
// direct or tunnel. Other traffic never enters the tunnel.
const (
	PathDesync = "desync"
	PathTunnel = "tunnel"
)

// GroupRoute is a canary group's routing scope.
type GroupRoute struct {
	ID           string   `json:"id"`
	DomainSuffix []string `json:"domain_suffix"`
}

func selectorTag(group, network string) string { return "sel-" + group + "-" + network }

// SelectiveRouteCIDRs captures public IPv4 only. IPv6 stays on the OS path so
// a network without working IPv6 never sees a synthetic IPv6 route.
func SelectiveRouteCIDRs() []string { return SplitDefaultCIDRs() }

func selectiveExclusions(p BuildParams) []string {
	var out []string
	for _, raw := range networkRouteExclusions(p) {
		if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Addr().Is4() {
			out = append(out, raw)
		}
	}
	return out
}

// buildSelectiveConfig is the 1.1 gateway: one process, IPv4 TCP 80/443 to the
// local helper, canary groups behind runtime selectors, everything else direct.
func buildSelectiveConfig(p BuildParams) (*SingBoxBuild, error) {
	if p.ListenIP == "" {
		p.ListenIP = "127.0.0.1"
	}
	if p.ListenPort == 0 {
		p.ListenPort = 18081
	}
	remote := p.Provider == ProviderWARP || p.Provider == ProviderReality
	direct := map[string]any{"type": "direct", "tag": "direct"}
	if p.EgressInterface != "" {
		direct["bind_interface"] = p.EgressInterface
	}
	rules := []any{map[string]any{"action": "sniff"}, map[string]any{"protocol": "dns", "action": "hijack-dns"}}
	inbounds := []any{map[string]any{"type": "socks", "tag": "socks-in", "listen": p.ListenIP, "listen_port": p.ListenPort}}
	if p.EnableTUN {
		if p.TUNInterface == "" {
			p.TUNInterface = "offveil"
		}
		if strings.EqualFold(p.TUNInterface, p.EgressInterface) {
			return nil, fmt.Errorf("physical egress must not be the TUN interface")
		}
		if p.TUNAddress == "" {
			p.TUNAddress = defaultTUNAddress
		}
		if p.TUNMTU <= 0 {
			p.TUNMTU = defaultTUNMTU
		}
		prefix, err := netip.ParsePrefix(p.TUNAddress)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("invalid TUN address family")
		}
		rules = append(rules, map[string]any{"ip_cidr": []string{prefix.Masked().String()}, "action": "reject", "method": "drop"})
		tun := map[string]any{"type": "tun", "tag": "tun-in", "address": []string{p.TUNAddress}, "mtu": p.TUNMTU,
			"auto_route": true, "strict_route": false, "route_address": SelectiveRouteCIDRs(),
			"route_exclude_address": selectiveExclusions(p), "stack": tunStack()}
		if name := tunInterfaceName(p.TUNInterface); name != "" {
			tun["interface_name"] = name
		}
		inbounds = append(inbounds, tun)
	}
	rules = append(rules,
		map[string]any{"ip_is_private": true, "outbound": "direct"},
		map[string]any{"ip_cidr": networkRouteExclusions(p), "outbound": "direct"})
	if len(p.ExcludeSuffixes) > 0 {
		rules = append(rules, map[string]any{"domain_suffix": p.ExcludeSuffixes, "outbound": "direct"})
	}
	if len(p.QuicRejectSuffixes) > 0 {
		quic := udp.QuicRejectRule()
		quic["domain_suffix"] = p.QuicRejectSuffixes
		rules = append(rules, quic)
	}
	var selectors []any
	if remote {
		for _, group := range p.Groups {
			if group.ID == "" || len(group.DomainSuffix) == 0 {
				continue
			}
			tcpDefault, udpDefault := PathDesync, "direct"
			if p.GroupPaths[group.ID] == PathTunnel {
				tcpDefault, udpDefault = PathTunnel, PathTunnel
			}
			selectors = append(selectors,
				map[string]any{"type": "selector", "tag": selectorTag(group.ID, "tcp"), "outbounds": []string{PathDesync, PathTunnel},
					"default": tcpDefault, "interrupt_exist_connections": true},
				map[string]any{"type": "selector", "tag": selectorTag(group.ID, "udp"), "outbounds": []string{"direct", PathTunnel},
					"default": udpDefault, "interrupt_exist_connections": true})
			rules = append(rules,
				map[string]any{"domain_suffix": group.DomainSuffix, "network": "tcp", "outbound": selectorTag(group.ID, "tcp")},
				map[string]any{"domain_suffix": group.DomainSuffix, "network": "udp", "outbound": selectorTag(group.ID, "udp")})
		}
	}
	rules = append(rules, map[string]any{"ip_version": 4, "network": "tcp", "port": []int{80, 443}, "outbound": PathDesync})

	dnsServer := map[string]any{"type": "https", "tag": "bootstrap", "server": "8.8.8.8", "server_port": 443, "path": "/dns-query"}
	if p.EgressInterface != "" {
		dnsServer["detour"] = "direct"
	}
	if p.DNSAddress != "" {
		host, portText, err := net.SplitHostPort(p.DNSAddress)
		addr, parseErr := netip.ParseAddr(host)
		port := 0
		if err == nil {
			_, _ = fmt.Sscan(portText, &port)
		}
		if err != nil || parseErr != nil || !addr.IsLoopback() || port < 1 || port > 65535 {
			return nil, fmt.Errorf("core DNS must use a loopback IP and valid port")
		}
		dnsServer = map[string]any{"type": "tcp", "tag": "bootstrap", "server": addr.String(), "server_port": port}
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"dns":       map[string]any{"servers": []any{dnsServer}, "final": "bootstrap", "strategy": "ipv4_only"},
		"inbounds":  inbounds,
		"outbounds": append([]any{direct}, selectors...),
		"route":     map[string]any{"auto_detect_interface": true, "default_domain_resolver": "bootstrap", "final": "direct", "rules": rules},
	}
	prependDesyncOutbound(cfg, p)
	if remote {
		if err := appendNetworkProvider(cfg, p); err != nil {
			return nil, err
		}
	}
	if p.ClashController != "" {
		addr, err := netip.ParseAddrPort(p.ClashController)
		if err != nil || !addr.Addr().IsLoopback() || p.ClashSecret == "" {
			return nil, fmt.Errorf("selector control must use loopback and a secret")
		}
		cfg["experimental"] = map[string]any{"clash_api": map[string]any{
			"external_controller": addr.String(), "secret": p.ClashSecret}}
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	provider := p.Provider
	if !remote {
		provider = ProviderDesync
	}
	return &SingBoxBuild{Provider: provider, JSON: raw}, nil
}
