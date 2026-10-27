package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

var testControls = []string{"control-a.test", "control-b.test", "control-c.test"}

// Test canaries: one persistent group and one crisis group.
var testDoc = ruleset.Document{
	Network: ruleset.NetworkPolicy{ControlHosts: testControls},
	Canaries: []ruleset.CanaryGroup{
		{ID: "chat", Label: "Chat", Kind: ruleset.CanaryPersistent, ProbeHosts: []string{"chat.test"}, DomainSuffix: []string{"chat.test"}},
		{ID: "news", Label: "News", Kind: ruleset.CanaryCrisis, ProbeHosts: []string{"news.test"}, DomainSuffix: []string{"news.test"}},
	},
}

type gatewayFixture struct {
	*tunnel.FakeSession
	results map[string]tunnel.FailClass // key: host or host|path
}

func (g *gatewayFixture) set(key string, class tunnel.FailClass) { g.results[key] = class }

func newGatewayFixture(tunnelReady bool) *gatewayFixture {
	g := &gatewayFixture{results: map[string]tunnel.FailClass{}}
	g.FakeSession = tunnel.NewFakeSession(tunnel.Info{Up: true, Healthy: true, Mode: "selective", ProviderID: tunnel.ProviderDesync, TunnelAvailable: tunnelReady}).
		WithHostGroups(map[string]string{"chat.test": "chat", "news.test": "news"}).
		WithProbe(func(host, path string) tunnel.FailClass {
			if class, ok := g.results[host+"|"+path]; ok {
				return class
			}
			if class, ok := g.results[host]; ok {
				return class
			}
			return tunnel.FailOK
		})
	return g
}

func networkTestEngine(t *testing.T) (*Engine, *gatewayFixture) {
	t.Helper()
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	e := activeBackgroundEngine(t)
	snap := ruleset.Snapshot{Doc: testDoc}
	e.rulesetSnap = &snap
	e.extraProbeHosts = append([]string(nil), testControls...)
	e.initGroupsLocked(testDoc)
	gateway := newGatewayFixture(false)
	e.tun = gateway
	e.layer = layerSelective
	e.classification = &Classification{DPI: DPIPresent}
	e.des = desync.NewFakeSession(desync.Info{Up: true, StrategyID: desync.PassThroughFirst(desync.NativeSafeStrategy()).ID})
	e.tunnelConfig = &tunnel.Config{Selective: true, Context: e.sessionContextLocked(), Groups: e.groupRoutesLocked(), GroupPaths: e.groupPathsLocked()}
	e.desyncConfig = &desync.Config{Context: e.sessionContextLocked(), ListenIP: "127.0.0.1", ListenPort: 18080, Strategy: desync.PassThroughFirst(desync.NativeSafeStrategy())}
	e.directProbe = func(_ context.Context, host string) tunnel.FailSignal {
		return tunnel.FailSignal{Target: host, Class: tunnel.FailOK}
	}
	e.cleanup.Register("layer", func() error {
		if e.des != nil {
			_ = e.des.Close()
		}
		if e.tun != nil {
			_ = e.tun.Close()
		}
		return nil
	})
	e.refreshNetworkStatusLocked()
	return e, gateway
}

func round(e *Engine, at time.Time) {
	e.mu.Lock()
	e.lastPathCheck = time.Time{}
	e.mu.Unlock()
	e.checkNetworkSession(e.sessionGeneration, at)
}

func TestHealthyGroupsReportProtected(t *testing.T) {
	e, _ := networkTestEngine(t)
	round(e, time.Now())
	st := e.Status()
	if st.State != StateActive || st.Summary != "Açık" || st.LastError != nil || !e.networkCheck.Healthy {
		t.Fatalf("status=%+v network=%+v", st, e.networkCheck)
	}
	for _, g := range e.networkCheck.Groups {
		if !g.Checked || !g.Healthy || g.Path != tunnel.PathDesync {
			t.Fatalf("group: %+v", g)
		}
	}
}

func TestFailingGroupScansThenEscalatesToTunnel(t *testing.T) {
	e, gateway := networkTestEngine(t)
	gateway.set("chat.test|desync", tunnel.FailReset)
	var scans []desync.ScanConfig
	e.scanDesync = func(_ context.Context, cfg desync.ScanConfig) desync.ScanResult {
		scans = append(scans, cfg)
		return desync.ScanResult{Reason: "exhausted"}
	}
	var prepared, rebuilt int
	var rebuiltCfg tunnel.Config
	e.prepareTunnel = func(context.Context, tunnel.Config, string) (tunnel.ProviderID, *tunnel.WARPProfile, []tunnel.EndpointTrial, error) {
		prepared++
		return tunnel.ProviderWARP, &tunnel.WARPProfile{EndpointIPv4: "162.159.192.1:500"}, []tunnel.EndpointTrial{{Endpoint: "162.159.192.1:2408", Class: tunnel.FailTimeout}}, nil
	}
	next := newGatewayFixture(true)
	next.set("chat.test|desync", tunnel.FailReset)
	e.startTunnel = func(cfg tunnel.Config) (tunnel.Session, error) {
		rebuilt++
		rebuiltCfg = cfg
		_ = next.SetGroupPath(context.Background(), "chat", cfg.GroupPaths["chat"])
		return next, nil
	}
	e.startDesync = func(desync.Config) (desync.Session, error) { return desync.NewFakeSession(desync.Info{}), nil }
	now := time.Now()
	round(e, now)
	if len(scans) != 0 || e.Status().Summary != "Açık" {
		t.Fatal("one failed round must not trigger repairs")
	}
	round(e, now.Add(networkCheckInterval))
	if len(scans) != 1 || len(scans[0].Required) != 1 || scans[0].Required[0] != "chat.test" || !scans[0].PassThroughFirst || scans[0].VerifyQuorum != 2 {
		t.Fatalf("scan must target the failing canary: %+v", scans)
	}
	round(e, now.Add(2*networkCheckInterval))
	if prepared != 1 || rebuilt != 1 || rebuiltCfg.TunnelProvider != tunnel.ProviderWARP || rebuiltCfg.GroupPaths["chat"] != tunnel.PathTunnel || rebuiltCfg.GroupPaths["news"] != tunnel.PathDesync {
		t.Fatalf("escalation: prepared=%d rebuilt=%d cfg=%+v", prepared, rebuilt, rebuiltCfg)
	}
	g := e.groupLocked("chat")
	if g.Path != tunnel.PathTunnel || !g.OK || g.Unreachable || e.Status().Summary != "Açık" || len(e.tunnelTrials) != 1 {
		t.Fatalf("group after escalation: %+v status=%+v", g, e.Status())
	}
	if network := e.networkCheck; network.Layers.Tunnel != "up" || network.Coverage != "dns_web_desync_tunnel" {
		t.Fatalf("tunnel layer: %+v", network.Layers)
	}
}

func TestExistingTunnelSwitchesGroupWithoutRebuild(t *testing.T) {
	e, _ := networkTestEngine(t)
	gateway := newGatewayFixture(true)
	gateway.set("chat.test|desync", tunnel.FailReset)
	e.tun = gateway
	e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
		return desync.ScanResult{Reason: "exhausted"}
	}
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) { t.Fatal("gateway rebuilt"); return nil, nil }
	now := time.Now()
	for i := range 3 {
		round(e, now.Add(time.Duration(i)*networkCheckInterval))
	}
	if moves := gateway.Moves(); len(moves) != 1 || moves[0] != "chat=tunnel" || e.groupLocked("chat").Path != tunnel.PathTunnel {
		t.Fatalf("moves=%v", gateway.Moves())
	}
}

func TestUnreachablePersistentGroupIsLimitedButCrisisGroupIsNot(t *testing.T) {
	for _, tc := range []struct {
		host, summary string
	}{{"chat.test", "Sınırlı koruma"}, {"news.test", "Açık"}} {
		t.Run(tc.host, func(t *testing.T) {
			e, gateway := networkTestEngine(t)
			gateway.set(tc.host, tunnel.FailTimeout)
			e.scanDesync = func(context.Context, desync.ScanConfig) desync.ScanResult {
				return desync.ScanResult{Reason: "exhausted"}
			}
			e.prepareTunnel = func(context.Context, tunnel.Config, string) (tunnel.ProviderID, *tunnel.WARPProfile, []tunnel.EndpointTrial, error) {
				return "", nil, nil, errors.New("no endpoint passed")
			}
			now := time.Now()
			for i := range 16 {
				round(e, now.Add(time.Duration(i)*networkCheckInterval))
			}
			st := e.Status()
			if st.Summary != tc.summary || st.LastError != nil || st.State != StateActive {
				t.Fatalf("status=%+v groups=%+v", st, e.networkCheck.Groups)
			}
			history := diag.ReadFailures()
			found := false
			for _, f := range history {
				found = found || f.Event == "tunnel_unavailable"
			}
			if !found {
				t.Fatalf("tunnel failure not journaled: %+v", history)
			}
		})
	}
}

func TestOfflineIsDistinguishedFromGatewayFailure(t *testing.T) {
	e, gateway := networkTestEngine(t)
	for _, host := range testControls {
		gateway.set(host, tunnel.FailTimeout)
	}
	direct := tunnel.FailTimeout
	e.directProbe = func(_ context.Context, host string) tunnel.FailSignal {
		return tunnel.FailSignal{Target: host, Class: direct}
	}
	round(e, time.Now())
	if st := e.Status(); st.Summary != "Bağlantı yok" || st.State != StateActive || st.LastError != nil {
		t.Fatalf("offline: %+v", st)
	}
	for _, host := range testControls {
		gateway.set(host, tunnel.FailOK)
	}
	direct = tunnel.FailOK
	round(e, time.Now().Add(networkCheckInterval))
	if st := e.Status(); st.Summary != "Açık" {
		t.Fatalf("recovered: %+v", st)
	}
}

func TestDNSLayerEscalatesWhenFilteringAppears(t *testing.T) {
	e, _ := networkTestEngine(t)
	e.tun, e.des, e.tunnelConfig, e.desyncConfig = nil, nil, nil, nil
	e.layer = layerDNS
	e.dns = offdns.NewFakeSession(offdns.Info{ListenAddr: "127.0.0.1:53"})
	dpi := DPINone
	e.classify = func(context.Context, DirectProbe, []string, []ruleset.CanaryGroup) Classification {
		return Classification{DPI: dpi}
	}
	starts := 0
	e.startDesync = func(desync.Config) (desync.Session, error) { return desync.NewFakeSession(desync.Info{}), nil }
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) { starts++; return newGatewayFixture(false), nil }
	e.closeOrphan = nil
	now := time.Now()
	round(e, now)
	if starts != 0 || e.layer != layerDNS {
		t.Fatal("unfiltered network got a gateway")
	}
	dpi = DPIPresent
	e.lastClassify = now.Add(-reclassifyInterval)
	round(e, now.Add(networkCheckInterval))
	if starts != 1 || e.layer != layerSelective || !e.dns.(*offdns.FakeSession).IPv4Only() {
		t.Fatalf("escalation: starts=%d layer=%s", starts, e.layer)
	}
}

func TestFallbackRetriesTCPLayerWithinBudget(t *testing.T) {
	e, _ := networkTestEngine(t)
	e.tun, e.des, e.tunnelConfig, e.desyncConfig = nil, nil, nil, nil
	e.layer, e.layerReason = layerFallback, "tun_unavailable"
	e.lastClassify = time.Now()
	e.closeOrphan = nil
	starts := 0
	e.startDesync = func(desync.Config) (desync.Session, error) { return desync.NewFakeSession(desync.Info{}), nil }
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) { starts++; return nil, errors.New("adapter busy") }
	now := time.Now()
	for i := range 10 {
		e.lastLayerTry = now.Add(-layerRetryInterval)
		round(e, now.Add(time.Duration(i)*networkCheckInterval))
	}
	if starts != layerRetryBudget || e.layer != layerFallback || e.Status().Summary != "Sınırlı koruma" {
		t.Fatalf("starts=%d layer=%s", starts, e.layer)
	}
}

func TestNetworkChecksDiscardReplacementSessionResults(t *testing.T) {
	e, _ := networkTestEngine(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	blocking := newGatewayFixture(false)
	var once sync.Once
	blocking.WithProbe(func(string, string) tunnel.FailClass {
		once.Do(func() { close(entered) })
		<-release
		return tunnel.FailReset
	})
	e.tun = blocking
	generation := e.sessionGeneration
	go func() { defer close(done); round(e, time.Now()) }()
	awaitBackground(t, entered)
	replaceBackgroundSession(e)
	close(release)
	awaitBackground(t, done)
	if g := e.groupLocked("chat"); g.Failures != 0 || g.Checked {
		t.Fatalf("old result reached a replacement session: %+v", g)
	}
	_ = generation
}

func TestRetainedActiveSnapshotReportsCurrentProtectionOff(t *testing.T) {
	e, _ := networkTestEngine(t)
	e.freezeSupportLocked()
	e.protection, e.state = false, StateStopped
	in := e.diagnosticsInputLocked()
	if !in.Cascade.Protection || in.System["protection_state"] != "off" || e.lastSupport.System["protection_state"] != "on" {
		t.Fatal("retained snapshot mutated or misreported current protection")
	}
}
