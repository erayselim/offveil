package tunnel

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNetworkRoutingDoesNotDependOnApplications(t *testing.T) {
	for _, remote := range []bool{false, true} {
		p := BuildParams{NetworkMode: true, Provider: ProviderDesync, EnableTUN: true}
		if remote {
			p.Provider = ProviderWARP
			p.UpstreamSOCKS = "127.0.0.1:18082"
		}
		build, err := BuildSingBox(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"process_name", "process_path", "domain_suffix", "discord", "imvu"} {
			if strings.Contains(string(build.JSON), forbidden) {
				t.Fatalf("application-specific routing: %s", forbidden)
			}
		}
		var cfg map[string]any
		if err := json.Unmarshal(build.JSON, &cfg); err != nil {
			t.Fatal(err)
		}
		route := cfg["route"].(map[string]any)
		quic := 0
		for _, raw := range route["rules"].([]any) {
			rule := raw.(map[string]any)
			if rule["protocol"] == "quic" && rule["action"] == "reject" {
				quic++
			}
		}
		if remote && (quic != 0 || route["final"] != "tunnel") {
			t.Fatal("remote mode must carry all public protocols")
		}
		if !remote && (quic != 1 || route["final"] != "direct") {
			t.Fatal("local mode must preserve opaque UDP and fallback QUIC")
		}
	}
}
