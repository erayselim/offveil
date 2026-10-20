package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/policy"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func endpointEngine(t *testing.T) *Engine {
	e := unavailableIMVUEngine(t)
	e.pathError, e.lastError, e.desyncScan = nil, nil, nil
	e.state = StateActive
	e.targets = []ipc.TargetStatus{{ID: "discord", Label: "Discord", Path: policy.PathDesync, Outcome: "ok"}}
	e.extraProbeHosts = secondaryProbeHosts(e.rulesetSnap.Doc)
	return e
}

func TestUpdaterFailureTriggersRecoveryDespiteWorkingHomepage(t *testing.T) {
	e := endpointEngine(t)
	if err := e.strategyStore.Put(e.policy.ASN(), desync.NativeSafeStrategy(), "discord.com"); err != nil {
		t.Fatal(err)
	}
	checked := 0
	e.tun = &tunnelHostCheck{e.tun.(*tunnel.FakeSession), func(host string) tunnel.FailSignal {
		checked++
		return tunnel.FailSignal{Target: host, Class: tunnel.FailTimeout}
	}}
	scanned := false
	e.scanDesync = func(_ context.Context, cfg desync.ScanConfig) desync.ScanResult {
		scanned = true
		seen := map[string]bool{}
		for _, host := range cfg.VerifyHosts {
			seen[host] = true
		}
		for _, host := range []string{"discord.com", "updates.discord.com", "gateway.discord.gg", "stable.dl2.discordapp.net"} {
			if !seen[host] {
				t.Errorf("recovery omitted %s", host)
			}
		}
		return desync.ScanResult{Reason: "exhausted"}
	}
	e.checkProtectedEndpointsSession(e.sessionGeneration)
	if _, ok := e.strategyStore.Lookup(e.policy.ASN()); ok {
		t.Error("homepage-only success remained pinned in ASN cache")
	}
	if !scanned || checked != 2 || e.pathError == nil || e.targets[0].Outcome != "retry" {
		t.Fatalf("updater failure hidden: checked=%d status=%+v", checked, e.Status())
	}
	e.tun = &tunnelHostCheck{tunnel.NewFakeSession(tunnel.Info{ProviderID: tunnel.ProviderDesync}), func(host string) tunnel.FailSignal {
		class := tunnel.FailOK
		if host == "updates.discord.com" {
			class = tunnel.FailTimeout
		}
		return tunnel.FailSignal{Target: host, Class: class}
	}}
	e.lastPathCheck = e.lastPathCheck.Add(-pathCheckInterval)
	e.recoverProtectedPath(e.sessionGeneration, e.lastPathCheck.Add(pathCheckInterval))
	if e.pathError == nil {
		t.Fatal("homepage success cleared updater failure")
	}
}

func TestTransientEndpointFailureKeepsAcceptedPolicy(t *testing.T) {
	e := endpointEngine(t)
	calls := 0
	e.tun = &tunnelHostCheck{e.tun.(*tunnel.FakeSession), func(host string) tunnel.FailSignal {
		calls++
		class := tunnel.FailOK
		if calls == 1 {
			class = tunnel.FailTimeout
		}
		return tunnel.FailSignal{Target: host, Class: class}
	}}
	e.checkProtectedEndpointsSession(e.sessionGeneration)
	if e.pathError != nil || e.targets[0].Path != policy.PathDesync {
		t.Fatal("single transient failure replaced healthy policy")
	}
}

func TestRetainedActiveSnapshotReportsCurrentProtectionOff(t *testing.T) {
	e := endpointEngine(t)
	e.freezeSupportLocked()
	e.protection, e.state = false, StateStopped
	in := e.diagnosticsInputLocked()
	if !in.Cascade.Protection || in.System["protection_state"] != "off" || e.lastSupport.System["protection_state"] != "on" {
		t.Fatal("current state was confused with retained cascade or mutated its snapshot")
	}
}

func TestEndpointChecksCannotPublishIntoReplacementSession(t *testing.T) {
	e := endpointEngine(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.tun = &tunnelHostCheck{e.tun.(*tunnel.FakeSession), func(host string) tunnel.FailSignal {
		once.Do(func() { close(entered) })
		<-release
		return tunnel.FailSignal{Target: host, Class: tunnel.FailTimeout}
	}}
	generation := e.sessionGeneration
	go func() { defer close(done); e.checkProtectedEndpointsSession(generation) }()
	finish := sync.OnceFunc(func() { close(release); <-done })
	defer finish()
	awaitBackground(t, entered)
	replaceBackgroundSession(e)
	finish()
	if e.pathError != nil || e.targets[0].Path != policy.PathDesync {
		t.Fatal("stale endpoint failure changed replacement session")
	}
}
