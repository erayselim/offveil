package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

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

func fakeNetworkSession(cfg Config, provider ProviderID) *session {
	s := &session{cfg: cfg, provider: provider, socks: net.JoinHostPort("127.0.0.1", fmt.Sprint(cfg.ListenPort)), controlHealthy: true}
	s.up.Store(true)
	for _, host := range cfg.ControlHosts {
		s.controls = append(s.controls, ControlResult{Target: host, Class: FailOK, At: time.Now().UTC().Format(time.RFC3339)})
	}
	return s
}

func networkFixture(t *testing.T) Config {
	t.Helper()
	return Config{NetworkMode: true, EnableTUN: true, ListenIP: "127.0.0.1", ListenPort: 18081, SkipStart: true, DataDir: t.TempDir(),
		ControlHosts: []string{"a.example", "b.example", "c.example"}, Reality: &RealityCredentials{Server: "relay.example", UUID: "test", PublicKey: "test"}}
}

func TestProviderPreflightNeverCreatesTUNAndRefreshPreservesGateway(t *testing.T) {
	cfg := networkFixture(t)
	cfg.NetworkRoutes = []ruleset.RouteRule{{Domains: cfg.ControlHosts, Path: "direct"}}
	var launches []Config
	trial := 0
	launcher := func(c Config, p providerAttempt) (*session, bool, FailClass, error) {
		launches = append(launches, c)
		if c.providerOnly {
			if len(c.NetworkRoutes) != 0 {
				t.Fatal("provider controls inherited DIRECT exceptions")
			}
			if c.EnableTUN || c.ListenPort == cfg.ListenPort {
				t.Fatal("provider trial shares TUN/gateway")
			}
			trial++
			if trial == 2 {
				return nil, false, FailReset, stageError("control_tls", "a.example", io.EOF)
			}
		}
		return fakeNetworkSession(c, p.ID), true, FailOK, nil
	}
	value, err := startNetworkWith(cfg, launcher)
	if err != nil {
		t.Fatal(err)
	}
	n := value.(*networkSession)
	defer n.Close()
	if len(launches) != 2 || !launches[0].providerOnly || !launches[1].EnableTUN {
		t.Fatal("gateway created before provider validation")
	}
	if launches[0].startupContext.Err() == nil || launches[0].Context.Err() != nil {
		t.Fatal("process lifetime bound to readiness budget")
	}
	oldGateway := n.gateway
	if err := n.RefreshTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.gateway != oldGateway || !oldGateway.Info().Up || n.Info().ProviderID != ProviderReality {
		t.Fatal("provider failover rebuilt the gateway")
	}
	if n.Info().Failures[0].Stage != "control_tls" || n.Info().Failures[0].Target != "a.example" {
		t.Fatal("failure stage/target lost")
	}
}

func TestFailedRemoteUpgradeKeepsWorkingLocalGateway(t *testing.T) {
	cfg := networkFixture(t)
	cfg.AllowlistOutbound = "desync"
	tunStarts := 0
	launcher := func(c Config, p providerAttempt) (*session, bool, FailClass, error) {
		if c.providerOnly {
			return nil, false, FailTimeout, context.DeadlineExceeded
		}
		tunStarts++
		return fakeNetworkSession(c, p.ID), true, FailOK, nil
	}
	value, err := startNetworkWith(cfg, launcher)
	if err != nil {
		t.Fatal(err)
	}
	n := value.(*networkSession)
	defer n.Close()
	old := n.gateway
	if err := n.RefreshTransport(context.Background()); err == nil {
		t.Fatal("failed remote candidates accepted")
	}
	if n.gateway != old || !old.Info().Up || tunStarts != 1 || n.Info().Mode != "local" {
		t.Fatal("failed preflight disrupted the local TUN")
	}
}

func TestSuccessfulPromotionRequiresVerifiedCoverage(t *testing.T) {
	cfg := networkFixture(t)
	cfg.AllowlistOutbound = "desync"
	launch := func(c Config, p providerAttempt) (*session, bool, FailClass, error) {
		return fakeNetworkSession(c, p.ID), true, FailOK, nil
	}
	value, err := startNetworkWith(cfg, launch)
	if err != nil {
		t.Fatal(err)
	}
	n := value.(*networkSession)
	defer n.Close()
	if err = n.RefreshTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if info := n.Info(); !info.Up || !info.Healthy || info.Mode != "remote" {
		t.Fatalf("unverified promotion accepted: %+v", info)
	}
}

func TestPromotionFailureRollsBackLocalGateway(t *testing.T) {
	cfg := networkFixture(t)
	cfg.AllowlistOutbound = "desync"
	tunStarts := 0
	var candidate *session
	launcher := func(c Config, p providerAttempt) (*session, bool, FailClass, error) {
		if c.providerOnly {
			candidate = fakeNetworkSession(c, p.ID)
			return candidate, true, FailOK, nil
		}
		tunStarts++
		if c.upstreamSOCKS != "" {
			return nil, false, FailDial, errors.New("fixture gateway failed")
		}
		return fakeNetworkSession(c, p.ID), true, FailOK, nil
	}
	value, err := startNetworkWith(cfg, launcher)
	if err != nil {
		t.Fatal(err)
	}
	n := value.(*networkSession)
	defer n.Close()
	if err := n.RefreshTransport(context.Background()); err == nil {
		t.Fatal("failed promotion reported success")
	}
	if !n.Info().Up || n.Info().Mode != "local" || tunStarts != 3 || candidate.Info().Up {
		t.Fatal("local gateway was not restored")
	}
}

func TestRemoteGatewayStartupFailureTriesLocalFallback(t *testing.T) {
	cfg := networkFixture(t)
	var candidate *session
	var remote, local int
	launcher := func(c Config, p providerAttempt) (*session, bool, FailClass, error) {
		if c.providerOnly {
			candidate = fakeNetworkSession(c, p.ID)
			return candidate, true, FailOK, nil
		}
		if c.upstreamSOCKS != "" {
			remote++
			return nil, false, FailDial, stageError("startup", "", errors.New("fixture remote gateway unavailable"))
		}
		local++
		if c.startupContext.Err() != nil || c.Context.Err() != nil {
			t.Fatal("local fallback inherited a spent or canceled readiness budget")
		}
		return fakeNetworkSession(c, p.ID), true, FailOK, nil
	}
	value, err := startNetworkWith(cfg, launcher)
	if err != nil {
		t.Fatalf("remote gateway error bypassed local fallback: %v", err)
	}
	defer value.Close()
	info := value.Info()
	if remote != 1 || local != 1 || candidate.Info().Up || !info.Up || info.Mode != "local" || info.Coverage != "tls_http_only" {
		t.Fatalf("fallback lifecycle: remote=%d local=%d info=%+v", remote, local, info)
	}
}

func TestFailedLocalGatewayRetainsStartupExitFacts(t *testing.T) {
	cfg := networkFixture(t)
	cfg.AllowlistOutbound = "desync"
	launcher := func(c Config, p providerAttempt) (*session, bool, FailClass, error) {
		child, err := failedAdapterChild(t, "The device is being removed")
		s := fakeNetworkSession(c, p.ID)
		s.up.Store(false)
		s.child, s.exitOrigin = child, "natural"
		return s, false, FailDial, stageError("startup", "", err)
	}
	value, err := startNetworkWith(cfg, launcher)
	var startup *StartupError
	if value != nil || !errors.As(err, &startup) || len(startup.Failures) != 1 {
		t.Fatalf("startup discarded gateway failure facts: %v %+v", err, startup)
	}
	f := startup.Failures[0]
	if f.Stage != "gateway_startup" || f.Class != FailDial || f.ExitOrigin != "natural" || f.Exit == nil ||
		f.Exit.StderrClass != "tun_setup" || f.Exit.Reason != "adapter_removing" {
		t.Fatalf("missing failure layer: %+v", f)
	}
}

func TestFailedGatewayControlsCannotPromoteVerifiedProvider(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close() // fail SOCKS/TLS without contacting a public host
		}
	}()
	defer func() { _ = listener.Close(); <-done }()
	cfg := networkFixture(t)
	cfg.AllowlistOutbound = "desync"
	launcher := func(c Config, p providerAttempt) (*session, bool, FailClass, error) {
		s := fakeNetworkSession(c, p.ID)
		s.socks = listener.Addr().String()
		return s, true, FailOK, nil
	}
	value, err := startNetworkWith(cfg, launcher)
	if err != nil {
		t.Fatal(err)
	}
	n := value.(*networkSession)
	defer n.Close()
	n.cfg.SkipStart = false
	if err := n.RefreshTransport(context.Background()); err == nil {
		t.Fatal("unverified gateway accepted a preflight-only provider")
	}
	info := n.Info()
	if info.Mode != "local" || info.Coverage != "tls_http_only" || info.Healthy || len(info.Failures) == 0 {
		t.Fatalf("failed gateway overstated protection: %+v", info)
	}
	last := info.Failures[len(info.Failures)-1]
	if last.Stage != "gateway_verification" || len(last.GatewayControls) != len(cfg.ControlHosts) {
		t.Fatalf("gateway verification facts lost: %+v", last)
	}
}
