package tunnel

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/udp"
)

const defaultTUNAddress6 = capture.TunIPv6

// NetworkRouteCIDRs captures both address families. Exclusions below preserve
// local traffic and the bootstrap transport independently of DNS or process names.
func NetworkRouteCIDRs() []string {
	return []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}
}

func networkRouteExclusions(p BuildParams) []string {
	var out []string
	for _, prefix := range capture.DefaultExcludePrefixes() {
		out = append(out, prefix.String())
	}
	out = append(out, "100.64.0.0/10")
	out = append(out, p.ExcludeCIDRs...)
	out = append(out, networkPeerExclusions(p.WARP, p.Reality)...)
	seen := map[string]bool{}
	clean := make([]string, 0, len(out))
	for _, raw := range out {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && !seen[prefix.Masked().String()] {
			value := prefix.Masked().String()
			seen[value] = true
			clean = append(clean, value)
		}
	}
	return clean
}

func networkPeerExclusions(warp *WARPProfile, reality *RealityCredentials) []string {
	var endpoints []string
	if warp != nil {
		endpoints = append(endpoints, warp.EndpointHost, warp.EndpointIPv4)
	}
	if reality != nil {
		endpoints = append(endpoints, reality.Server)
	}
	var out []string
	for _, endpoint := range endpoints {
		host := endpoint
		if value, _, err := net.SplitHostPort(endpoint); err == nil {
			host = value
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()).String())
		}
	}
	return out
}

func buildNetworkConfig(p BuildParams) (*SingBoxBuild, error) {
	if p.ListenIP == "" {
		p.ListenIP = "127.0.0.1"
	}
	if p.ListenPort == 0 {
		p.ListenPort = 18081
	}
	if p.Provider == "" {
		p.Provider = ProviderDesync
	}
	local := p.Provider == ProviderDesync && p.UpstreamSOCKS == ""
	direct := map[string]any{"type": "direct", "tag": "direct"}
	if p.EgressInterface != "" {
		direct["bind_interface"] = p.EgressInterface
	}
	// Rule-specific bootstrap addresses also apply to SOCKS inbounds: a direct
	// probe or private destination must not accidentally enter a remote relay.
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
		if p.TUNAddress6 == "" {
			p.TUNAddress6 = defaultTUNAddress6
		}
		if p.TUNMTU <= 0 {
			p.TUNMTU = defaultTUNMTU
		}
		var owned []string
		for i, address := range []string{p.TUNAddress, p.TUNAddress6} {
			prefix, err := netip.ParsePrefix(address)
			if err != nil || (i == 0 && !prefix.Addr().Is4()) || (i == 1 && !prefix.Addr().Is6()) {
				return nil, fmt.Errorf("invalid TUN address family")
			}
			owned = append(owned, prefix.Masked().String())
		}
		// Check the owned subnet before private DIRECT rules to prevent a loop
		// back through the gateway's own synthetic interface.
		rules = append(rules, map[string]any{"ip_cidr": owned, "action": "reject", "method": "drop"})
		tun := map[string]any{"type": "tun", "tag": "tun-in", "address": []string{p.TUNAddress, p.TUNAddress6}, "mtu": p.TUNMTU,
			"auto_route": true, "strict_route": false, "route_address": NetworkRouteCIDRs(), "route_exclude_address": networkRouteExclusions(p), "stack": tunStack()}
		if name := tunInterfaceName(p.TUNInterface); name != "" {
			tun["interface_name"] = name
		}
		inbounds = append(inbounds, tun)
	}
	if !p.ProviderOnly {
		rules = append(rules, map[string]any{"ip_is_private": true, "outbound": "direct"},
			map[string]any{"ip_cidr": networkRouteExclusions(p), "outbound": "direct"})
	}
	for _, rule := range p.NetworkRoutes {
		if p.ProviderOnly {
			continue
		}
		if rule.Path != "direct" {
			return nil, fmt.Errorf("network routes support only explicit direct exceptions")
		}
		if len(rule.Domains) > 0 {
			rules = append(rules, map[string]any{"domain": rule.Domains, "outbound": "direct"})
		}
		if len(rule.DomainSuffix) > 0 {
			rules = append(rules, map[string]any{"domain_suffix": rule.DomainSuffix, "outbound": "direct"})
		}
	}
	final := "tunnel"
	if local {
		final = "direct"
		// The physical-source-bound helper is IPv4-only. Unsupported families
		// retain direct connectivity instead of entering an incompatible proxy.
		quic := udp.QuicRejectRule()
		quic["ip_version"] = 4
		rules = append(rules, quic,
			map[string]any{"ip_version": 4, "network": "tcp", "protocol": []string{"tls", "http"}, "outbound": "desync"},
			map[string]any{"ip_version": 4, "network": "tcp", "port": []int{80, 443}, "outbound": "desync"})
	}
	dnsServer := map[string]any{"type": "https", "tag": "bootstrap", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query"}
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
		"log":      map[string]any{"level": "warn", "timestamp": true},
		"dns":      map[string]any{"servers": []any{dnsServer}, "final": "bootstrap", "strategy": "prefer_ipv4"},
		"inbounds": inbounds, "outbounds": []any{direct},
		"route": map[string]any{"auto_detect_interface": true, "default_domain_resolver": "bootstrap", "final": final, "rules": rules},
	}
	if local {
		prependDesyncOutbound(cfg, p)
	} else if p.UpstreamSOCKS != "" {
		host, port := splitDesyncSOCKS(p.UpstreamSOCKS)
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.IsLoopback() {
			return nil, fmt.Errorf("provider gateway must use a loopback SOCKS address")
		}
		cfg["outbounds"] = append(cfg["outbounds"].([]any), map[string]any{"type": "socks", "tag": "tunnel", "server": host, "server_port": port, "version": "5"})
	} else {
		if err := appendNetworkProvider(cfg, p); err != nil {
			return nil, err
		}
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return &SingBoxBuild{Provider: p.Provider, JSON: raw}, nil
}

func appendNetworkProvider(cfg map[string]any, p BuildParams) error {
	switch p.Provider {
	case ProviderWARP:
		if p.WARP == nil {
			return fmt.Errorf("warp profile required")
		}
		host, port := splitHostPort(p.WARP.EndpointHost, 2408)
		if p.WARP.EndpointIPv4 != "" {
			host, port = splitHostPort(p.WARP.EndpointIPv4, 2408)
		}
		var addresses []string
		for _, address := range []string{p.WARP.AddressIPv4, p.WARP.AddressIPv6} {
			if address == "" {
				continue
			}
			if !strings.Contains(address, "/") {
				addr, err := netip.ParseAddr(address)
				if err != nil {
					return fmt.Errorf("invalid wireguard address")
				}
				address = netip.PrefixFrom(addr, addr.BitLen()).String()
			}
			addresses = append(addresses, address)
		}
		endpoint := map[string]any{"type": "wireguard", "tag": "tunnel", "system": false, "mtu": 1280, "address": addresses, "private_key": p.WARP.PrivateKey,
			"peers": []any{map[string]any{"address": host, "port": port, "public_key": p.WARP.PeerPublicKey, "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "reserved": []int{int(p.WARP.Reserved[0]), int(p.WARP.Reserved[1]), int(p.WARP.Reserved[2])}}}}
		if p.EgressInterface != "" {
			endpoint["bind_interface"] = p.EgressInterface
		}
		cfg["endpoints"] = []any{endpoint}
	case ProviderReality:
		if p.Reality == nil {
			return fmt.Errorf("reality credentials required")
		}
		outbound := map[string]any{"type": "vless", "tag": "tunnel", "server": p.Reality.Server, "server_port": p.Reality.ServerPort, "uuid": p.Reality.UUID, "flow": p.Reality.Flow,
			"tls": map[string]any{"enabled": true, "server_name": p.Reality.ServerName, "utls": map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{"enabled": true, "public_key": p.Reality.PublicKey, "short_id": p.Reality.ShortID}}}
		if p.EgressInterface != "" {
			outbound["bind_interface"] = p.EgressInterface
		}
		cfg["outbounds"] = append(cfg["outbounds"].([]any), outbound)
	default:
		return fmt.Errorf("unsupported remote provider")
	}
	return nil
}
