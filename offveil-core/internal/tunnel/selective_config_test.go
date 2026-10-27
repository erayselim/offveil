package tunnel

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func selectiveTestWARP(t *testing.T) *WARPProfile {
	t.Helper()
	keys, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return &WARPProfile{PrivateKey: keys.Private, PeerPublicKey: peer.Public, AddressIPv4: "172.16.0.2", AddressIPv6: "2606:4700:110::2", EndpointIPv4: "162.159.192.1:2408"}
}

func selectiveParams(warp *WARPProfile) BuildParams {
	p := BuildParams{Selective: true, Provider: ProviderDesync, EnableTUN: true, DNSAddress: "127.0.0.1:53", EgressInterface: "Ethernet",
		Groups:          []GroupRoute{{ID: "chat", DomainSuffix: []string{"chat.test"}}, {ID: "news", DomainSuffix: []string{"news.test"}}},
		GroupPaths:      map[string]string{"news": PathTunnel},
		ExcludeSuffixes: []string{"games.test"}}
	if warp != nil {
		p.Provider, p.WARP = ProviderWARP, warp
		p.ClashController, p.ClashSecret = "127.0.0.1:19090", "secret"
	}
	return p
}

func decodeConfig(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestSelectiveConfigNeverFullTunnels(t *testing.T) {
	for name, warp := range map[string]*WARPProfile{"local": nil, "with-tunnel": selectiveTestWARP(t)} {
		t.Run(name, func(t *testing.T) {
			build, err := BuildSingBox(selectiveParams(warp))
			if err != nil {
				t.Fatal(err)
			}
			cfg := decodeConfig(t, build.JSON)
			route := cfg["route"].(map[string]any)
			if route["final"] != "direct" {
				t.Fatalf("final=%v", route["final"])
			}
			if cfg["dns"].(map[string]any)["strategy"] != "ipv4_only" {
				t.Fatal("selective DNS must stay IPv4-only")
			}
			var tun map[string]any
			for _, in := range cfg["inbounds"].([]any) {
				if m := in.(map[string]any); m["type"] == "tun" {
					tun = m
				}
			}
			if tun == nil || !reflect.DeepEqual(tun["route_address"], []any{"0.0.0.0/1", "128.0.0.0/1"}) || len(tun["address"].([]any)) != 1 {
				t.Fatalf("TUN must capture IPv4 only: %+v", tun)
			}
			for _, raw := range tun["route_exclude_address"].([]any) {
				if strings.Contains(raw.(string), ":") {
					t.Fatalf("IPv6 exclusion on an IPv4-only TUN: %v", raw)
				}
			}
			if int(tun["mtu"].(float64)) != defaultTUNMTU {
				t.Fatalf("mtu=%v", tun["mtu"])
			}
			rules := route["rules"].([]any)
			excludeAt, desyncAt := -1, -1
			for i, r := range rules {
				rule := r.(map[string]any)
				if reflect.DeepEqual(rule["domain_suffix"], []any{"games.test"}) && rule["outbound"] == "direct" {
					excludeAt = i
				}
				if rule["outbound"] == PathDesync && rule["network"] == "tcp" {
					desyncAt = i
				}
				if rule["protocol"] == "quic" {
					t.Fatalf("QUIC must not be rejected by default: %v", rule)
				}
				if rule["outbound"] == PathTunnel {
					t.Fatalf("no rule may send traffic to the tunnel directly: %v", rule)
				}
			}
			if excludeAt < 0 || desyncAt < excludeAt || desyncAt != len(rules)-1 {
				t.Fatalf("exclude=%d desync=%d rules=%d", excludeAt, desyncAt, len(rules))
			}
			selectors := 0
			for _, o := range cfg["outbounds"].([]any) {
				m := o.(map[string]any)
				if m["type"] == "selector" {
					selectors++
					if m["tag"] == "sel-news-tcp" && m["default"] != PathTunnel || m["tag"] == "sel-chat-tcp" && m["default"] != PathDesync || m["tag"] == "sel-chat-udp" && m["default"] != "direct" {
						t.Fatalf("selector default: %+v", m)
					}
				}
			}
			if warp == nil && (selectors != 0 || cfg["experimental"] != nil || cfg["endpoints"] != nil) {
				t.Fatal("local gateway must not carry tunnel selectors")
			}
			if warp != nil && (selectors != 4 || cfg["experimental"] == nil || cfg["endpoints"] == nil) {
				t.Fatalf("selectors=%d", selectors)
			}
		})
	}
}

func TestSelectiveConfigRejectsUnsafeControl(t *testing.T) {
	p := selectiveParams(selectiveTestWARP(t))
	p.ClashController = "0.0.0.0:9090"
	if _, err := BuildSingBox(p); err == nil {
		t.Fatal("non-loopback selector control accepted")
	}
	p.ClashController, p.ClashSecret = "127.0.0.1:9090", ""
	if _, err := BuildSingBox(p); err == nil {
		t.Fatal("selector control without secret accepted")
	}
}

func TestWARPEndpointCandidatesCoverPortsAndKeepRememberedFirst(t *testing.T) {
	got := WARPEndpointCandidates(&WARPProfile{EndpointIPv4: "162.159.192.9:2408"}, "162.159.193.10:4500")
	if got[0] != "162.159.193.10:4500" || got[1] != "162.159.192.9:2408" {
		t.Fatalf("order: %v", got[:2])
	}
	seen := map[string]bool{}
	for _, endpoint := range got {
		if seen[endpoint] {
			t.Fatalf("duplicate %s", endpoint)
		}
		seen[endpoint] = true
	}
	for _, port := range []string{":2408", ":500", ":1701", ":4500"} {
		if !seen["162.159.192.1"+port] {
			t.Fatalf("missing port %s", port)
		}
	}
}

func TestNativeSelectorSwitchKeepsGatewayRunning(t *testing.T) {
	bin := os.Getenv("OFFVEIL_SINGBOX_TEST")
	if bin == "" {
		t.Skip("set OFFVEIL_SINGBOX_TEST to the pinned sing-box binary")
	}
	warp := selectiveTestWARP(t)
	warp.EndpointIPv4 = "127.0.0.1:9"
	cfg := Config{Selective: true, BinaryPath: bin, DataDir: t.TempDir(), ListenIP: "127.0.0.1", ListenPort: 18197,
		DesyncSOCKS: "127.0.0.1:18198", DNSAddress: "", TunnelProvider: ProviderWARP, WARPProfile: warp,
		Groups: []GroupRoute{{ID: "chat", DomainSuffix: []string{"chat.test"}}}}
	s, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sel := s.(SelectiveSession)
	pid := s.Info().PID
	if !sel.TunnelAvailable() || sel.GroupPaths()["chat"] != PathDesync {
		t.Fatalf("initial: %+v", s.Info())
	}
	ctx := t.Context()
	if err := sel.SetGroupPath(ctx, "chat", PathTunnel); err != nil {
		t.Fatal(err)
	}
	if err := sel.SetGroupPath(ctx, "chat", PathDesync); err != nil {
		t.Fatal(err)
	}
	if err := sel.SetGroupPath(ctx, "missing", PathTunnel); err == nil {
		t.Fatal("unknown group accepted")
	}
	if info := s.Info(); !info.Up || info.PID != pid || info.GroupPaths["chat"] != PathDesync {
		t.Fatalf("gateway restarted or path lost: %+v", info)
	}
}

func TestNativeSelectiveConfig(t *testing.T) {
	bin := os.Getenv("OFFVEIL_SINGBOX_TEST")
	if bin == "" {
		t.Skip("set OFFVEIL_SINGBOX_TEST to the pinned sing-box binary")
	}
	for name, warp := range map[string]*WARPProfile{"local": nil, "with-tunnel": selectiveTestWARP(t)} {
		t.Run(name, func(t *testing.T) {
			p := selectiveParams(warp)
			p.QuicRejectSuffixes = []string{"news.test"}
			build, err := BuildSingBox(p)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "sing-box.json")
			if err = os.WriteFile(path, build.JSON, 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
				t.Fatalf("native config rejected: %v\n%s", err, out)
			}
		})
	}
}
