package tunnel_test

import (
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

// DIRECT exceptions must also apply to HTTP/3. Keep DNS hijacking ahead of
// those exceptions and QUIC rejection ahead of the protected service routes.
func TestBuildSingBoxDirectExceptionsBeforeQUIC(t *testing.T) {
	for _, provider := range []tunnel.ProviderID{tunnel.ProviderDesync, tunnel.ProviderWARP, tunnel.ProviderReality} {
		for _, mode := range []struct {
			name string
			tun  bool
		}{{"tun", true}, {"socks", false}} {
			t.Run(string(provider)+"/"+mode.name, func(t *testing.T) {
				params := tunnel.BuildParams{
					Provider:       provider,
					EnableTUN:      mode.tun,
					DirectDomains:  []string{"steampowered.com"},
					TunnelDomains:  []string{"discord.com"},
					SpecialDomains: []string{"discord.com", "imvu.com"},
				}
				// Config-only fixtures; no providers are contacted.
				switch provider {
				case tunnel.ProviderWARP:
					params.WARP = &tunnel.WARPProfile{
						PrivateKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
						AddressIPv4:   "172.16.0.2",
						PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
						EndpointIPv4:  "192.0.2.1:2408",
					}
				case tunnel.ProviderReality:
					params.Reality = &tunnel.RealityCredentials{
						Server:     "example.com",
						ServerPort: 443,
						UUID:       "00000000-0000-0000-0000-000000000001",
						PublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
						ShortID:    "abcd",
						ServerName: "www.cloudflare.com",
						Flow:       "xtls-rprx-vision",
					}
				}
				build, err := tunnel.BuildSingBox(params)
				if err != nil {
					t.Fatal(err)
				}
				rules := routeRuleMaps(t, build.JSON)
				sniff := indexRule(rules, func(r map[string]any) bool { return r["action"] == "sniff" })
				dns := indexRule(rules, func(r map[string]any) bool {
					return r["action"] == "hijack-dns" && hasStr(asStrings(r["protocol"]), "dns")
				})
				quic := indexRule(rules, isQuicReject)
				if sniff < 0 || dns <= sniff || quic <= dns {
					t.Fatalf("expected sniff before DNS hijack before QUIC reject: sniff=%d dns=%d quic=%d", sniff, dns, quic)
				}
				for _, exception := range []struct {
					name  string
					match func(map[string]any) bool
				}{
					{"DIRECT domains", isExcludeDirect},
					{"private IPs", func(r map[string]any) bool {
						return r["ip_is_private"] == true && r["outbound"] == "direct"
					}},
				} {
					idx := indexRule(rules, exception.match)
					if idx <= dns || idx >= quic {
						t.Errorf("%s must follow DNS hijack and precede QUIC reject: dns=%d exception=%d quic=%d", exception.name, dns, idx, quic)
					}
				}
				protected := indexRule(rules, func(r map[string]any) bool {
					return hasStr(asStrings(r["domain_suffix"]), "discord.com") &&
						(r["outbound"] == "tunnel" || r["outbound"] == "desync")
				})
				if protected <= quic {
					t.Errorf("protected service route must follow QUIC reject: quic=%d protected=%d", quic, protected)
				}
				if mode.tun {
					assertProtocolSplit(t, build.JSON)
				}
			})
		}
	}
}
