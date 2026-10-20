package tunnel

import (
	"encoding/json"
	"testing"
)

func TestCoreDNSUsesLiteralLoopbackWithoutBootstrapOrTunnelDetour(t *testing.T) {
	build, err := BuildSingBox(BuildParams{Provider: ProviderDesync, EnableTUN: true, DNSAddress: "127.0.0.1:1053", EgressInterface: "physical-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(build.JSON, &cfg); err != nil {
		t.Fatal(err)
	}
	server := cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if server["type"] != "tcp" || server["server"] != "127.0.0.1" || server["server_port"] != float64(1053) || server["detour"] != nil || server["bind_interface"] != nil || server["domain_resolver"] != nil {
		t.Fatalf("local resolver depends on another DNS/tunnel/interface: %+v", server)
	}
	tun := cfg["inbounds"].([]any)[1].(map[string]any)
	excluded := map[string]bool{}
	for _, raw := range tun["route_exclude_address"].([]any) {
		excluded[raw.(string)] = true
	}
	for _, cidr := range []string{"127.0.0.0/8", "1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "9.9.9.9/32"} {
		if !excluded[cidr] {
			t.Errorf("DNS bootstrap can loop through capture: %s", cidr)
		}
	}
}

func TestCoreDNSRejectsHostnamePublicAddressAndInvalidPort(t *testing.T) {
	for _, address := range []string{"localhost:53", "1.1.1.1:53", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1"} {
		if _, err := BuildSingBox(BuildParams{Provider: ProviderDesync, DNSAddress: address}); err == nil {
			t.Errorf("accepted %q", address)
		}
	}
}
