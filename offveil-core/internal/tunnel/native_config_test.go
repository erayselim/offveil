package tunnel

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeSingBoxConfig(t *testing.T) {
	bin := os.Getenv("OFFVEIL_SINGBOX_TEST")
	if bin == "" {
		t.Skip("set OFFVEIL_SINGBOX_TEST to the pinned sing-box binary")
	}
	keys, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	warp := &WARPProfile{PrivateKey: keys.Private, PeerPublicKey: peer.Public, AddressIPv4: "172.16.0.2", AddressIPv6: "2606:4700:110::2", EndpointIPv4: "127.0.0.1:2408"}
	publicKey := strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(peer.Public), "=")
	for name, params := range map[string]BuildParams{
		"local-dual-stack":   {NetworkMode: true, Provider: ProviderDesync, EnableTUN: true, DNSAddress: "127.0.0.1:53"},
		"remote-dual-stack":  {NetworkMode: true, Provider: ProviderWARP, EnableTUN: true, UpstreamSOCKS: "127.0.0.1:18082", DNSAddress: "127.0.0.1:53"},
		"wireguard-provider": {NetworkMode: true, ProviderOnly: true, Provider: ProviderWARP, WARP: warp, DNSAddress: "127.0.0.1:53"},
		"reality-provider":   {NetworkMode: true, ProviderOnly: true, Provider: ProviderReality, DNSAddress: "127.0.0.1:53", Reality: &RealityCredentials{Server: "127.0.0.1", ServerPort: 443, UUID: "de04add9-5c68-4bab-950c-08cd5320df18", PublicKey: publicKey, ServerName: "example.com", Flow: "xtls-rprx-vision"}},
	} {
		t.Run(name, func(t *testing.T) {
			build, err := BuildSingBox(params)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "sing-box.json")
			if err = os.WriteFile(path, build.JSON, 0600); err != nil {
				t.Fatal(err)
			}
			// Validation only: a configuration containing TUN is never executed.
			if out, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
				t.Fatalf("native config rejected: %v\n%s", err, out)
			}
		})
	}
}
