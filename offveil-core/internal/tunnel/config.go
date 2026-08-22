package tunnel

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/erayselim/offveil/offveil-core/internal/udp"
)

const (
	defaultTUNAddress = "10.87.0.1/30"
	defaultTUNMTU     = 1280
)

// SingBoxBuild is the generated selective tunnel config + metadata.
type SingBoxBuild struct {
	Provider ProviderID
	JSON     []byte
}

// BuildParams is the full sing-box generator input (SOCKS + optional TUN dataplane).
type BuildParams struct {
	Provider      ProviderID
	WARP          *WARPProfile
	Reality       *RealityCredentials
	ListenIP      string
	ListenPort    int
	TunnelDomains []string
	DirectDomains []string
	EnableTUN     bool
	TUNInterface  string
	TUNAddress    string
	TUNMTU        int
	RouteCIDRs    []string
	ExcludeCIDRs  []string
	// AllowlistOutbound tags the allowlist path: "desync" or "tunnel".
	AllowlistOutbound string
	DesyncSOCKSHost   string
	DesyncSOCKSPort   int
}

// BuildSingBoxConfig produces a selective SOCKS→tunnel config (no TUN).
// Peer/outbound never installs a full default-route; route.final = direct.
func BuildSingBoxConfig(provider ProviderID, warp *WARPProfile, reality *RealityCredentials, listenIP string, listenPort int, tunnelDomains, directDomains []string) (*SingBoxBuild, error) {
	return BuildSingBox(BuildParams{
		Provider:      provider,
		WARP:          warp,
		Reality:       reality,
		ListenIP:      listenIP,
		ListenPort:    listenPort,
		TunnelDomains: tunnelDomains,
		DirectDomains: directDomains,
	})
}

// BuildSingBox produces SOCKS + optional TUN inbound. TUN uses auto_route with
// route_address only (never 0.0.0.0/0). Allowlisted TUN traffic goes to desync
// or tunnel; everything else stays direct via route.final.
func BuildSingBox(p BuildParams) (*SingBoxBuild, error) {
	if p.ListenIP == "" {
		p.ListenIP = "127.0.0.1"
	}
	if p.ListenPort == 0 {
		p.ListenPort = 18081
	}
	if len(p.TunnelDomains) == 0 {
		p.TunnelDomains = DefaultTunnelDomains()
	}
	if len(p.DirectDomains) == 0 {
		p.DirectDomains = DefaultDirectDomains()
	}
	allowOut := strings.ToLower(strings.TrimSpace(p.AllowlistOutbound))
	if allowOut == "" {
		if p.Provider == ProviderDesync {
			allowOut = "desync"
		} else {
			allowOut = "tunnel"
		}
	}
	if p.Provider == "" {
		if allowOut == "desync" {
			p.Provider = ProviderDesync
		}
	}

	if p.EnableTUN {
		if p.TUNInterface == "" {
			p.TUNInterface = "offveil"
		}
		if p.TUNAddress == "" {
			p.TUNAddress = defaultTUNAddress
		}
		if p.TUNMTU <= 0 {
			p.TUNMTU = defaultTUNMTU
		}
		p.RouteCIDRs = FilterRouteCIDRs(p.RouteCIDRs, p.ExcludeCIDRs, p.WARP, p.TUNAddress)
		if len(p.RouteCIDRs) == 0 {
			return nil, fmt.Errorf("tun enabled but no public route CIDRs (refusing default-route)")
		}
	}

	inbounds := []any{
		map[string]any{
			"type":        "socks",
			"tag":         "socks-in",
			"listen":      p.ListenIP,
			"listen_port": p.ListenPort,
		},
	}
	if p.EnableTUN {
		inbounds = append(inbounds, map[string]any{
			"type":                  "tun",
			"tag":                   "tun-in",
			"interface_name":        p.TUNInterface,
			"address":               []string{p.TUNAddress},
			"mtu":                   p.TUNMTU,
			"auto_route":            true,
			"strict_route":          false,
			"route_address":         p.RouteCIDRs,
			"route_exclude_address": defaultRouteExclude(),
			"stack":                 "system",
		})
	}

	cfg := map[string]any{
		"log": map[string]any{
			"level":     "warn",
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{
					"type":        "https",
					"tag":         "doh",
					"server":      "1.1.1.1",
					"server_port": 443,
					"path":        "/dns-query",
				},
			},
			"final":    "doh",
			"strategy": "ipv4_only",
		},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{
			"auto_detect_interface":   true,
			"default_domain_resolver": "doh",
			"final":                   "direct",
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				// Drop QUIC (UDP/443) so TCP HTTPS stays on tunnel/desync paths.
				udp.QuicRejectRule(),
				map[string]any{
					"domain_suffix": p.DirectDomains,
					"outbound":      "direct",
				},
				map[string]any{
					"ip_is_private": true,
					"outbound":      "direct",
				},
			},
		},
	}

	switch p.Provider {
	case ProviderDesync:
		host := p.DesyncSOCKSHost
		port := p.DesyncSOCKSPort
		if host == "" {
			host = "127.0.0.1"
		}
		if port == 0 {
			port = 18080
		}
		outbounds := cfg["outbounds"].([]any)
		outbounds = append([]any{
			map[string]any{
				"type":        "socks",
				"tag":         "desync",
				"server":      host,
				"server_port": port,
				"version":     "5",
			},
		}, outbounds...)
		cfg["outbounds"] = outbounds
		appendAllowlistRules(cfg, p, "desync")

	case ProviderWARP:
		if p.WARP == nil {
			return nil, fmt.Errorf("warp profile required")
		}
		epHost, epPort := splitHostPort(p.WARP.EndpointHost, 2408)
		// Prefer IPv4 endpoint when available (avoids DoH dependency for engage.).
		if p.WARP.EndpointIPv4 != "" {
			h, pport := splitHostPort(p.WARP.EndpointIPv4, 2408)
			epHost, epPort = h, pport
		}
		addr := p.WARP.AddressIPv4
		if !strings.Contains(addr, "/") {
			addr = addr + "/32"
		}
		addresses := []string{addr}
		if p.WARP.AddressIPv6 != "" {
			v6 := p.WARP.AddressIPv6
			if !strings.Contains(v6, "/") {
				v6 = v6 + "/128"
			}
			addresses = append(addresses, v6)
		}
		peer := map[string]any{
			"address":     epHost,
			"port":        epPort,
			"public_key":  p.WARP.PeerPublicKey,
			"allowed_ips": []string{"0.0.0.0/0", "::/0"}, // within WG; routing stays selective via rules
			"reserved":    []int{int(p.WARP.Reserved[0]), int(p.WARP.Reserved[1]), int(p.WARP.Reserved[2])},
		}
		cfg["endpoints"] = []any{
			map[string]any{
				"type":        "wireguard",
				"tag":         "tunnel",
				"system":      false, // userspace WG - capture TUN is the sing-box tun inbound
				"mtu":         1280,
				"address":     addresses,
				"private_key": p.WARP.PrivateKey,
				"peers":       []any{peer},
			},
		}
		appendAllowlistRules(cfg, p, "tunnel")

	case ProviderReality:
		if p.Reality == nil {
			return nil, fmt.Errorf("reality credentials required")
		}
		outbounds := cfg["outbounds"].([]any)
		outbounds = append([]any{
			map[string]any{
				"type":        "vless",
				"tag":         "tunnel",
				"server":      p.Reality.Server,
				"server_port": p.Reality.ServerPort,
				"uuid":        p.Reality.UUID,
				"flow":        p.Reality.Flow,
				"tls": map[string]any{
					"enabled":     true,
					"server_name": p.Reality.ServerName,
					"utls": map[string]any{
						"enabled":     true,
						"fingerprint": "chrome",
					},
					"reality": map[string]any{
						"enabled":    true,
						"public_key": p.Reality.PublicKey,
						"short_id":   p.Reality.ShortID,
					},
				},
			},
		}, outbounds...)
		cfg["outbounds"] = outbounds
		appendAllowlistRules(cfg, p, "tunnel")

	default:
		return nil, fmt.Errorf("unknown provider %q", p.Provider)
	}

	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return &SingBoxBuild{Provider: p.Provider, JSON: raw}, nil
}

func appendAllowlistRules(cfg map[string]any, p BuildParams, outbound string) {
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if p.EnableTUN {
		// Every packet that hit selected-route → TUN is allowlist traffic.
		rules = append(rules, map[string]any{
			"inbound":  "tun-in",
			"outbound": outbound,
		})
	}
	rules = append(rules, map[string]any{
		"domain_suffix": p.TunnelDomains,
		"outbound":      outbound,
	})
	cfg["route"].(map[string]any)["rules"] = rules
}

func defaultRouteExclude() []string {
	return []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"224.0.0.0/4",
		"255.255.255.255/32",
	}
}

// FilterRouteCIDRs drops default routes, private nets, public DNS, the TUN
// subnet, and the WARP endpoint so capture cannot black-hole or loop egress.
func FilterRouteCIDRs(cidrs, extraExclude []string, warp *WARPProfile, tunAddr string) []string {
	exclude := map[string]struct{}{
		"1.1.1.1/32": {},
		"1.0.0.1/32": {},
		"8.8.8.8/32": {},
		"8.8.4.4/32": {},
		"9.9.9.9/32": {},
	}
	for _, e := range extraExclude {
		if p, err := normalizeCIDR(e); err == nil {
			exclude[p] = struct{}{}
		}
	}
	if tunAddr != "" {
		if p, err := netip.ParsePrefix(tunAddr); err == nil {
			exclude[p.Masked().String()] = struct{}{}
			exclude[netip.PrefixFrom(p.Addr(), 32).String()] = struct{}{}
		}
	}
	if warp != nil {
		for _, ep := range []string{warp.EndpointIPv4, warp.EndpointHost} {
			host, _ := splitHostPort(ep, 2408)
			if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
				exclude[netip.PrefixFrom(ip, 32).String()] = struct{}{}
			}
		}
	}

	var out []string
	seen := map[string]struct{}{}
	for _, raw := range cidrs {
		p, err := normalizeCIDR(raw)
		if err != nil {
			continue
		}
		pref, err := netip.ParsePrefix(p)
		if err != nil || pref.Bits() == 0 || !pref.Addr().Is4() {
			continue
		}
		if pref.Addr().IsPrivate() || pref.Addr().IsLoopback() || pref.Addr().IsLinkLocalUnicast() || pref.Addr().IsMulticast() {
			continue
		}
		if _, skip := exclude[p]; skip {
			continue
		}
		if _, skip := exclude[netip.PrefixFrom(pref.Addr(), 32).String()]; skip {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func normalizeCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty")
	}
	if !strings.Contains(s, "/") {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return "", err
		}
		return netip.PrefixFrom(ip, 32).String(), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", err
	}
	return p.Masked().String(), nil
}

func splitHostPort(hostport string, defPort int) (string, int) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "engage.cloudflareclient.com", defPort
	}
	// Strip brackets for IPv6 literal with port.
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		n, _ := strconv.Atoi(p)
		if n == 0 {
			n = defPort
		}
		return h, n
	}
	// host:port without brackets, or "ip:0" from Cloudflare.
	if i := strings.LastIndex(hostport, ":"); i > 0 {
		portStr := hostport[i+1:]
		if n, err := strconv.Atoi(portStr); err == nil {
			if n == 0 {
				n = defPort
			}
			return hostport[:i], n
		}
	}
	return hostport, defPort
}
