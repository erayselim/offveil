package tunnel_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func TestDefaultLists(t *testing.T) {
	td := tunnel.DefaultTunnelDomains()
	if len(td) < 4 {
		t.Fatalf("tunnel domains too small: %v", td)
	}
	dd := tunnel.DefaultDirectDomains()
	if !tunnel.IsDirectHost("store.steampowered.com", dd) {
		t.Fatal("expected steam subdomain DIRECT")
	}
	if tunnel.IsDirectHost("discord.com", dd) {
		t.Fatal("discord must not be DIRECT")
	}
}

func TestReservedFromClientID(t *testing.T) {
	id := base64.StdEncoding.EncodeToString([]byte{171, 85, 205, 1})
	r, err := tunnel.ReservedFromClientID(id)
	if err != nil {
		t.Fatal(err)
	}
	if r[0] != 171 || r[1] != 85 || r[2] != 205 {
		t.Fatalf("reserved=%v", r)
	}
}

func TestBuildSingBoxWARPSelective(t *testing.T) {
	warp := &tunnel.WARPProfile{
		PrivateKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		AddressIPv4:   "172.16.0.2",
		PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		EndpointHost:  "engage.cloudflareclient.com:2408",
		EndpointIPv4:  "162.159.192.1:2408",
		Reserved:      [3]byte{1, 2, 3},
	}
	build, err := tunnel.BuildSingBoxConfig(
		tunnel.ProviderWARP, warp, nil,
		"127.0.0.1", 18081,
		tunnel.DefaultTunnelDomains(),
		tunnel.DefaultDirectDomains(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(build.JSON, &m); err != nil {
		t.Fatal(err)
	}
	raw := string(build.JSON)
	if strings.Contains(raw, `"final": "tunnel"`) {
		t.Fatal("must not default-route all traffic to tunnel")
	}
	if !strings.Contains(raw, `"final": "direct"`) {
		t.Fatal("expected final=direct")
	}
	if !strings.Contains(raw, "steampowered.com") {
		t.Fatal("expected steam DIRECT rule")
	}
	if !strings.Contains(raw, "discord.com") {
		t.Fatal("expected discord tunnel rule")
	}
	if !strings.Contains(raw, `"system": false`) {
		t.Fatal("expected userspace wireguard (system:false)")
	}
	if !strings.Contains(raw, `"network": "udp"`) || !strings.Contains(raw, `"action": "reject"`) {
		t.Fatal("expected QUIC UDP/443 reject rule")
	}
}

func TestBuildSingBoxTUNSelectedRoute(t *testing.T) {
	warp := &tunnel.WARPProfile{
		PrivateKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		AddressIPv4:   "172.16.0.2",
		PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		EndpointHost:  "engage.cloudflareclient.com:2408",
		EndpointIPv4:  "162.159.192.1:2408",
		Reserved:      [3]byte{1, 2, 3},
	}
	build, err := tunnel.BuildSingBox(tunnel.BuildParams{
		Provider:      tunnel.ProviderWARP,
		WARP:          warp,
		ListenIP:      "127.0.0.1",
		ListenPort:    18081,
		EnableTUN:     true,
		TUNInterface:  "offveil",
		TUNAddress:    "10.87.0.1/30",
		RouteCIDRs:    []string{"162.159.128.233/32", "0.0.0.0/0", "1.1.1.1/32", "162.159.192.1/32"},
		TunnelDomains: []string{"discord.com"},
		DirectDomains: []string{"steampowered.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(build.JSON)
	if !strings.Contains(raw, `"type": "tun"`) {
		t.Fatal("expected tun inbound")
	}
	if !strings.Contains(raw, `"162.159.128.233/32"`) {
		t.Fatal("expected selected-route CIDR")
	}
	var m map[string]any
	if err := json.Unmarshal(build.JSON, &m); err != nil {
		t.Fatal(err)
	}
	foundDefault := false
	for _, in := range m["inbounds"].([]any) {
		im := in.(map[string]any)
		if im["type"] == "tun" {
			for _, cidr := range im["route_address"].([]any) {
				if cidr == "0.0.0.0/0" {
					foundDefault = true
				}
			}
		}
	}
	if foundDefault {
		t.Fatal("tun route_address must not contain default route")
	}
	if strings.Contains(raw, `"162.159.192.1/32"`) {
		t.Fatal("WARP endpoint must not be captured")
	}
	if strings.Contains(raw, `"1.1.1.1/32"`) {
		t.Fatal("public DNS must not be captured")
	}
	if !strings.Contains(raw, `"inbound": "tun-in"`) {
		t.Fatal("expected tun-in catch-all to tunnel")
	}
}

func TestBuildSingBoxDesyncDataplane(t *testing.T) {
	build, err := tunnel.BuildSingBox(tunnel.BuildParams{
		Provider:        tunnel.ProviderDesync,
		EnableTUN:       true,
		RouteCIDRs:      []string{"162.159.128.233/32"},
		DesyncSOCKSHost: "127.0.0.1",
		DesyncSOCKSPort: 18080,
		TunnelDomains:   []string{"discord.com"},
		DirectDomains:   []string{"steampowered.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(build.JSON)
	if !strings.Contains(raw, `"tag": "desync"`) {
		t.Fatal("expected desync socks outbound")
	}
	if strings.Contains(raw, `"type": "wireguard"`) {
		t.Fatal("desync dataplane must not start WARP")
	}
}

func TestBuildSingBoxTUNRequiresCIDRs(t *testing.T) {
	_, err := tunnel.BuildSingBox(tunnel.BuildParams{
		Provider:  tunnel.ProviderDesync,
		EnableTUN: true,
	})
	if err == nil {
		t.Fatal("expected error when TUN has no CIDRs")
	}
}

func TestBuildSingBoxReality(t *testing.T) {
	r := &tunnel.RealityCredentials{
		Server:     "example.com",
		ServerPort: 443,
		UUID:       "00000000-0000-0000-0000-000000000001",
		PublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ShortID:    "abcd",
		ServerName: "www.cloudflare.com",
		Flow:       "xtls-rprx-vision",
	}
	build, err := tunnel.BuildSingBoxConfig(
		tunnel.ProviderReality, nil, r,
		"127.0.0.1", 18081, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(build.JSON), `"type": "vless"`) {
		t.Fatal("expected vless outbound")
	}
	if !strings.Contains(string(build.JSON), `"reality"`) {
		t.Fatal("expected reality tls")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	a, err := tunnel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := tunnel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if a.Private == b.Private || a.Public == "" {
		t.Fatalf("bad keys a=%+v b=%+v", a, b)
	}
}

func TestFakeSession(t *testing.T) {
	f := tunnel.NewFakeSession(tunnel.Info{Up: true, LastProbe: tunnel.FailOK})
	if !f.Info().Selective || !f.Info().Up {
		t.Fatalf("%+v", f.Info())
	}
	sig := f.ProbeTLS("discord.com")
	if sig.Class != tunnel.FailOK {
		t.Fatalf("%+v", sig)
	}
}

func TestProviderOrderWARPOnly(t *testing.T) {
	dir := t.TempDir()
	order := tunnel.ProviderOrder(tunnel.Config{}, dir)
	if len(order) != 1 || order[0].ID != tunnel.ProviderWARP {
		t.Fatalf("%+v", order)
	}
}

func TestProviderOrderRealityThenWARP(t *testing.T) {
	dir := t.TempDir()
	r := &tunnel.RealityCredentials{
		Server: "example.com", UUID: "u", PublicKey: "k", ShortID: "ab",
	}
	order := tunnel.ProviderOrder(tunnel.Config{Reality: r}, dir)
	if len(order) != 2 || order[0].ID != tunnel.ProviderReality || order[1].ID != tunnel.ProviderWARP {
		t.Fatalf("%+v", order)
	}
	off := false
	order = tunnel.ProviderOrder(tunnel.Config{Reality: r, Failover: &off}, dir)
	if len(order) != 1 || order[0].ID != tunnel.ProviderReality {
		t.Fatalf("failover off: %+v", order)
	}
}

func TestSelectProviderPreferRealityMissing(t *testing.T) {
	_, _, err := tunnel.SelectProvider(tunnel.Config{PreferReality: true}, t.TempDir())
	if err == nil {
		t.Fatal("expected error")
	}
}
