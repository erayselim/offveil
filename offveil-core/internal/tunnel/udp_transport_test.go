package tunnel

import (
	"encoding/json"
	"testing"
)

func TestDirectEgressDoesNotPinLocalSOCKS(t *testing.T) {
	build, err := BuildSingBox(BuildParams{Provider: ProviderDesync, EnableTUN: true, EgressInterface: "Ethernet"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(build.JSON, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, out := range cfg.Outbounds {
		switch out["tag"] {
		case "direct":
			if out["bind_interface"] != "Ethernet" {
				t.Fatal("direct traffic lost physical egress binding")
			}
		case "desync":
			if out["bind_interface"] != nil || out["inet4_bind_address"] != nil {
				t.Fatal("physical binding would break loopback SOCKS")
			}
		}
	}
}

func TestTUNSubnetCannotReenterDirectOutbound(t *testing.T) {
	build, err := BuildSingBox(BuildParams{Provider: ProviderDesync, EnableTUN: true, TUNAddress: "10.91.0.1/29"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(build.JSON, &cfg); err != nil {
		t.Fatal(err)
	}
	dns, guard, firstDirect := -1, -1, -1
	for i, rule := range cfg.Route.Rules {
		if rule["action"] == "hijack-dns" {
			dns = i
		}
		if rule["outbound"] == "direct" && firstDirect < 0 {
			firstDirect = i
		}
		if rule["action"] == "reject" && rule["ip_cidr"] != nil {
			guard = i
			prefixes := rule["ip_cidr"].([]any)
			if len(prefixes) != 1 || prefixes[0] != "10.91.0.0/29" || rule["method"] != "drop" {
				t.Fatalf("wrong self-route guard: %+v", rule)
			}
		}
	}
	if dns < 0 || guard <= dns || firstDirect <= guard {
		t.Fatalf("DNS and self-route precedence: dns=%d guard=%d direct=%d", dns, guard, firstDirect)
	}
}

func TestEgressRejectsOwnTUNInterface(t *testing.T) {
	if _, err := BuildSingBox(BuildParams{Provider: ProviderDesync, EnableTUN: true, TUNInterface: "offveil", EgressInterface: "offveil"}); err == nil {
		t.Fatal("TUN accepted as physical egress")
	}
}
