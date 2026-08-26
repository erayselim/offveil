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
	for _, h := range []string{
		"store.steampowered.com",
		"auth.riotgames.com",
		"launcher.epicgames.com",
		"ac-client-ws.faceit.com",
	} {
		if !tunnel.IsDirectHost(h, dd) {
			t.Fatalf("expected %s DIRECT", h)
		}
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
	rules := routeRuleMaps(t, build.JSON)
	if idx := indexRule(rules, isQuicReject); idx < 0 {
		t.Fatal("expected sniffed QUIC reject")
	}
}

func tunRouteAddress(t *testing.T, raw []byte) []string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, in := range m["inbounds"].([]any) {
		im := in.(map[string]any)
		if im["type"] != "tun" {
			continue
		}
		var out []string
		for _, cidr := range im["route_address"].([]any) {
			out = append(out, cidr.(string))
		}
		return out
	}
	t.Fatal("no tun inbound")
	return nil
}

func routeRuleMaps(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	route := m["route"].(map[string]any)
	var out []map[string]any
	for _, r := range route["rules"].([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

func asStrings(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{x}
	default:
		return nil
	}
}

func asInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

func hasStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func indexRule(rules []map[string]any, pred func(map[string]any) bool) int {
	for i, r := range rules {
		if pred(r) {
			return i
		}
	}
	return -1
}

func isQuicReject(r map[string]any) bool {
	if r["action"] != "reject" {
		return false
	}
	protos := asStrings(r["protocol"])
	return hasStr(protos, "quic")
}

func isExcludeDirect(r map[string]any) bool {
	if r["outbound"] != "direct" {
		return false
	}
	return len(asStrings(r["domain_suffix"])) > 0
}

func isSpecialUDPDesync(r map[string]any) bool {
	if r["outbound"] != "desync" || r["network"] != "udp" {
		return false
	}
	return len(asStrings(r["domain_suffix"])) > 0
}

func isGenericUDPDirect(r map[string]any) bool {
	if r["outbound"] != "direct" || r["network"] != "udp" {
		return false
	}
	if len(asStrings(r["domain_suffix"])) > 0 {
		return false
	}
	if r["port"] != nil {
		return false
	}
	return true
}

func isTCP443Desync(r map[string]any) bool {
	return r["outbound"] == "desync" && r["network"] == "tcp" && asInt(r["port"]) == 443
}

func assertProtocolSplit(t *testing.T, raw []byte) {
	t.Helper()
	rules := routeRuleMaps(t, raw)
	quicIdx := indexRule(rules, isQuicReject)
	if quicIdx < 0 {
		t.Fatal("missing sniffed QUIC reject")
	}
	if _, ok := rules[quicIdx]["port"]; ok {
		t.Fatal("QUIC reject must not use port 443 (game UDP)")
	}
	exclIdx := indexRule(rules, isExcludeDirect)
	if exclIdx < 0 {
		t.Fatal("missing exclude domain_suffix → direct")
	}
	if !hasStr(asStrings(rules[exclIdx]["domain_suffix"]), "steampowered.com") {
		t.Fatalf("exclude missing steam: %v", rules[exclIdx]["domain_suffix"])
	}
	udpIdx := indexRule(rules, isGenericUDPDirect)
	if udpIdx < 0 {
		t.Fatal("missing generic UDP → direct")
	}
	tcpIdx := indexRule(rules, isTCP443Desync)
	if tcpIdx < 0 {
		t.Fatal("missing TCP/443 → desync")
	}
	if exclIdx >= udpIdx || exclIdx >= tcpIdx {
		t.Fatalf("exclude idx=%d must precede UDP=%d and TCP443=%d", exclIdx, udpIdx, tcpIdx)
	}
	if spec := indexRule(rules, isSpecialUDPDesync); spec >= 0 && spec >= udpIdx {
		t.Fatalf("special UDP desync idx=%d must precede generic UDP=%d", spec, udpIdx)
	}
	if udpIdx >= tcpIdx {
		t.Fatalf("generic UDP idx=%d must precede TCP/443 desync idx=%d", udpIdx, tcpIdx)
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
	addrs := tunRouteAddress(t, build.JSON)
	for _, cidr := range addrs {
		if cidr == "0.0.0.0/0" {
			t.Fatal("tun route_address must not contain 0.0.0.0/0")
		}
		if cidr == "1.1.1.1/32" {
			t.Fatal("public DNS must not be in route_address")
		}
		if cidr == "162.159.192.1/32" {
			t.Fatal("WARP endpoint must not be in route_address")
		}
	}
	hasAllow := false
	for _, cidr := range addrs {
		if cidr == "162.159.128.233/32" {
			hasAllow = true
		}
	}
	if !hasAllow {
		t.Fatal("expected selected-route CIDR")
	}
	raw := string(build.JSON)
	if strings.Contains(raw, `"inbound": "tun-in"`) {
		t.Fatal("tun-in catch-all must not send every packet to tunnel/desync")
	}
	if !strings.Contains(raw, `"tag": "desync"`) {
		t.Fatal("mixed WARP dataplane must keep ByeDPI desync outbound")
	}
}

func TestBuildSingBoxInvertDefault(t *testing.T) {
	build, err := tunnel.BuildSingBox(tunnel.BuildParams{
		Provider:        tunnel.ProviderDesync,
		EnableTUN:       true,
		DesyncSOCKSHost: "127.0.0.1",
		DesyncSOCKSPort: 18080,
		SpecialDomains:  []string{"discord.com"},
		DirectDomains:   []string{"steampowered.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	addrs := tunRouteAddress(t, build.JSON)
	want := map[string]bool{"0.0.0.0/1": false, "128.0.0.0/1": false}
	for _, cidr := range addrs {
		if cidr == "0.0.0.0/0" {
			t.Fatal("split-default must not be 0.0.0.0/0")
		}
		if _, ok := want[cidr]; ok {
			want[cidr] = true
		}
	}
	for cidr, ok := range want {
		if !ok {
			t.Fatalf("missing split-default %s in %v", cidr, addrs)
		}
	}
	raw := string(build.JSON)
	if strings.Contains(raw, `"inbound": "tun-in"`) {
		t.Fatal("no tun-in catch-all")
	}
	if strings.Contains(raw, `"final": "desync"`) || strings.Contains(raw, `"final": "tunnel"`) {
		t.Fatal("route.final must stay direct")
	}
	assertProtocolSplit(t, build.JSON)
}

func TestBuildSingBoxProtocolSplit(t *testing.T) {
	build, err := tunnel.BuildSingBox(tunnel.BuildParams{
		Provider:        tunnel.ProviderDesync,
		EnableTUN:       true,
		DesyncSOCKSHost: "127.0.0.1",
		DesyncSOCKSPort: 18080,
		SpecialDomains:  []string{"discord.com"},
		DirectDomains:   tunnel.DefaultDirectDomains(),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertProtocolSplit(t, build.JSON)
	rules := routeRuleMaps(t, build.JSON)
	excl := rules[indexRule(rules, isExcludeDirect)]
	suf := asStrings(excl["domain_suffix"])
	for _, want := range []string{"steampowered.com", "riotgames.com", "epicgames.com", "faceit.com"} {
		if !hasStr(suf, want) {
			t.Fatalf("exclude missing %s: %v", want, suf)
		}
	}
	spec := indexRule(rules, isSpecialUDPDesync)
	udp := indexRule(rules, isGenericUDPDirect)
	if spec < 0 {
		t.Fatal("missing special UDP → desync")
	}
	if spec >= udp {
		t.Fatalf("special UDP idx=%d must precede generic UDP idx=%d", spec, udp)
	}
}

func TestBuildSingBoxDesyncDataplane(t *testing.T) {
	build, err := tunnel.BuildSingBox(tunnel.BuildParams{
		Provider:        tunnel.ProviderDesync,
		EnableTUN:       true,
		RouteCIDRs:      []string{"162.159.128.233/32"},
		DesyncSOCKSHost: "127.0.0.1",
		DesyncSOCKSPort: 18080,
		SpecialDomains:  []string{"discord.com"},
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
	if strings.Contains(raw, `"outbound": "tunnel"`) {
		t.Fatal("desync-only must not route special suffixes to missing tunnel outbound")
	}
}

func TestBuildSingBoxEmptyCIDRsSplitDefault(t *testing.T) {
	build, err := tunnel.BuildSingBox(tunnel.BuildParams{
		Provider:  tunnel.ProviderDesync,
		EnableTUN: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	addrs := tunRouteAddress(t, build.JSON)
	if len(addrs) != 2 {
		t.Fatalf("route_address=%v want split-default", addrs)
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
