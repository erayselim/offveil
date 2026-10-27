package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
)

func TestNetworkDualStackCoverageAndLoopExclusions(t *testing.T) {
	build, err := BuildSingBox(BuildParams{NetworkMode: true, EnableTUN: true, Provider: ProviderWARP, UpstreamSOCKS: "127.0.0.1:18082", EgressInterface: "physical-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(build.JSON, &cfg); err != nil {
		t.Fatal(err)
	}
	tun := cfg["inbounds"].([]any)[1].(map[string]any)
	contains := func(value any, want string) bool {
		for _, v := range value.([]any) {
			if v == want {
				return true
			}
		}
		return false
	}
	for _, route := range NetworkRouteCIDRs() {
		if !contains(tun["route_address"], route) {
			t.Errorf("missing public route %s", route)
		}
	}
	if !contains(tun["address"], capture.TunIPv6) {
		t.Fatal("IPv6 TUN address missing")
	}
	for _, prefix := range capture.DefaultExcludePrefixes() {
		if !contains(tun["route_exclude_address"], prefix.String()) {
			t.Errorf("missing loop/bootstrap exclusion %s", prefix)
		}
	}
	for _, raw := range cfg["outbounds"].([]any) {
		outbound := raw.(map[string]any)
		if outbound["tag"] == "direct" && outbound["bind_interface"] != "physical-fixture" {
			t.Fatal("direct traffic not pinned")
		}
		if outbound["tag"] == "tunnel" && outbound["bind_interface"] != nil {
			t.Fatal("loopback provider SOCKS must not be pinned")
		}
	}
}

func TestNetworkExactAndSuffixDirectExceptionsRemainDistinct(t *testing.T) {
	p := BuildParams{NetworkMode: true, Provider: ProviderWARP, UpstreamSOCKS: "127.0.0.1:18082", NetworkRoutes: []ruleset.RouteRule{{Domains: []string{"exact.example"}, Path: "direct"}, {DomainSuffix: []string{"suffix.example"}, Path: "direct"}}}
	build, err := BuildSingBox(p)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(build.JSON, &cfg)
	exact, suffix := false, false
	for _, raw := range cfg["route"].(map[string]any)["rules"].([]any) {
		rule := raw.(map[string]any)
		if domains, ok := rule["domain"].([]any); ok && domains[0] == "exact.example" {
			exact = true
			if rule["domain_suffix"] != nil {
				t.Fatal("exact host widened to suffix")
			}
		}
		if domains, ok := rule["domain_suffix"].([]any); ok && domains[0] == "suffix.example" {
			suffix = true
		}
	}
	if !exact || !suffix {
		t.Fatal("explicit direct exceptions were lost")
	}
	p.NetworkRoutes[0].Path = "desync"
	if _, err := BuildSingBox(p); err == nil {
		t.Fatal("unsupported custom route silently ignored")
	}
}

func TestProviderControlRoutingCannotUseDirectExceptions(t *testing.T) {
	build, err := BuildSingBox(BuildParams{NetworkMode: true, ProviderOnly: true, Provider: ProviderWARP, UpstreamSOCKS: "127.0.0.1:18082", NetworkRoutes: []ruleset.RouteRule{{Domains: []string{"control-a.test", "control-b.test"}, Path: "direct"}}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(build.JSON, &cfg); err != nil {
		t.Fatal(err)
	}
	route := cfg["route"].(map[string]any)
	if route["final"] != "tunnel" {
		t.Fatal("provider health bypassed the remote route")
	}
	for _, raw := range route["rules"].([]any) {
		if raw.(map[string]any)["outbound"] == "direct" {
			t.Fatal("provider controls can succeed through a DIRECT exception")
		}
	}
}

func TestLocalFallbackDoesNotSendIPv6ToIPv4OnlyHelper(t *testing.T) {
	build, err := BuildSingBox(BuildParams{NetworkMode: true, Provider: ProviderDesync})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(build.JSON, &cfg)
	for _, raw := range cfg["route"].(map[string]any)["rules"].([]any) {
		rule := raw.(map[string]any)
		if rule["outbound"] == "desync" || rule["protocol"] == "quic" {
			if rule["ip_version"] != float64(4) {
				t.Fatal("unsupported IPv6 flow sent to local IPv4-only helper")
			}
		}
	}
	if cfg["route"].(map[string]any)["final"] != "direct" {
		t.Fatal("unsupported local protocols must retain direct reachability")
	}
}

func TestControlQuorumToleratesOneIndependentFailure(t *testing.T) {
	hosts := []string{"a.example", "b.example", "c.example"}
	for failures := 0; failures <= 3; failures++ {
		results, ok := checkControls(context.Background(), hosts, 2, func(_ context.Context, host string) FailSignal {
			class := FailOK
			if strings.Index("abc", host[:1]) < failures {
				class = FailReset
			}
			return FailSignal{Target: host, Class: class}
		})
		if ok != (failures <= 1) || len(results) != 3 {
			t.Fatalf("%d failures: healthy=%t results=%+v", failures, ok, results)
		}
	}
	for _, cfg := range []Config{{ControlHosts: []string{"same.example", "SAME.EXAMPLE"}}, {ControlHosts: hosts, ControlQuorum: 1}, {ControlHosts: []string{"1.1.1.1", "b.example"}}} {
		if err := normalizeControls(&cfg); err == nil {
			t.Fatal("unsafe control quorum accepted")
		}
	}
}

func TestDialFailuresAreNotAllTimeouts(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want FailClass
	}{
		{io.ErrUnexpectedEOF, FailEOF}, {io.EOF, FailEOF}, {context.DeadlineExceeded, FailTimeout},
		{fmt.Errorf("wrapped: %w", syscall.ECONNRESET), FailReset}, {syscall.ECONNREFUSED, FailRefused},
		{errors.New("x509: unknown certificate authority"), FailCertificate}, {errors.New("tls: handshake failure"), FailProbe},
		{errors.New("network unreachable"), FailDial},
	} {
		if got := classifyDialErr(tc.err); got != tc.want {
			t.Errorf("%v: %s want %s", tc.err, got, tc.want)
		}
	}
}

