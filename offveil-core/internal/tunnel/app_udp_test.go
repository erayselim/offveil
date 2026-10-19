package tunnel

import (
	"encoding/json"
	"regexp"
	"testing"
)

func TestApplicationUDPUsesPackagePathWithoutHostname(t *testing.T) {
	p := BuildParams{Provider: ProviderWARP, TunnelDomains: []string{"imvu.com"}, SpecialDomains: []string{"discord.com"}}
	rules := applicationUDPRules(p, false)
	matched := func(name, path string) string {
		for _, raw := range rules {
			rule := raw.(map[string]any)
			for _, value := range stringList(rule["process_name"]) {
				if name == value {
					return rule["outbound"].(string)
				}
			}
			for _, pattern := range stringList(rule["process_path_regex"]) {
				if regexp.MustCompile(pattern).MatchString(path) {
					return rule["outbound"].(string)
				}
			}
		}
		return "direct"
	}
	for _, tc := range []struct{ name, path, want string }{
		{"Discord.exe", "", "desync"},
		{"IMVUClient.exe", "", "tunnel"},
		{"helper", "/Applications/Discord.app/Contents/Frameworks/helper", "desync"},
		{"helper", "/Applications/IMVU Desktop.app/Contents/MacOS/helper", "tunnel"},
		{"RobloxPlayer", "/Applications/Roblox.app/Contents/MacOS/RobloxPlayer", "direct"},
		{"game.exe", "", "direct"},
	} {
		if got := matched(tc.name, tc.path); got != tc.want {
			t.Errorf("%s: path=%s want=%s", tc.name, got, tc.want)
		}
	}
	p.DirectDomains = []string{"imvu.com", "discord.com"}
	if len(applicationUDPRules(p, false)) != 0 {
		t.Fatal("explicit direct package was overridden")
	}
}

func stringList(v any) []string {
	if v == nil {
		return nil
	}
	return v.([]string)
}

func TestQUICRejectIsScopedToProtectedTraffic(t *testing.T) {
	build, err := BuildSingBox(BuildParams{Provider: ProviderDesync, EnableTUN: true, SpecialDomains: []string{"discord.com", "imvu.com"}})
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
	found := 0
	for _, rule := range cfg.Route.Rules {
		if rule["action"] != "reject" || rule["protocol"] != "quic" {
			continue
		}
		found++
		if rule["domain_suffix"] == nil && rule["process_name"] == nil && rule["process_path_regex"] == nil {
			t.Fatal("unrelated downloads still lose QUIC")
		}
	}
	if found == 0 {
		t.Fatal("protected QUIC was not rejected")
	}
}
