package engine

import (
	"sync"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/policy"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func promotionEngine(t *testing.T) *Engine {
	e := endpointEngine(t)
	e.targets[0].Path, e.targets[0].Outcome = policy.PathTunnel, "retry"
	message := unavailablePathMessage(e.targets)
	e.pathError, e.lastError, e.state = &message, &message, StateDegraded
	e.tunnelConfig = &tunnel.Config{Context: e.sessionContextLocked(), AllowlistOutbound: "desync", DNSAddress: "127.0.0.1:53", EnableTUN: true}
	return e
}

func TestEndpointFailurePromotesOnlyDataplaneAndVerifiesServiceHosts(t *testing.T) {
	e := promotionEngine(t)
	original := e.tun.(*tunnel.FakeSession)
	helper := e.des
	checked := map[string]bool{}
	e.startTunnel = func(cfg tunnel.Config) (tunnel.Session, error) {
		if !original.Closed() || cfg.ProbeHost != "updates.discord.com" || cfg.DNSAddress != "127.0.0.1:53" || cfg.AllowlistOutbound != "tunnel" || len(cfg.TunnelDomains) == 0 {
			t.Fatalf("invalid promotion: %+v", cfg)
		}
		return &tunnelHostCheck{tunnel.NewFakeSession(tunnel.Info{ProviderID: tunnel.ProviderWARP, Up: true}), func(host string) tunnel.FailSignal {
			checked[host] = true
			return tunnel.FailSignal{Target: host, Class: tunnel.FailOK}
		}}, nil
	}
	e.promoteEndpointTunnelSession(e.sessionGeneration, "updates.discord.com")
	if len(checked) != 4 || e.pathError != nil || e.Status().State != StateActive || e.des != helper || e.tun.ProviderID() != tunnel.ProviderWARP {
		t.Fatalf("provider adoption incomplete: checked=%v status=%+v", checked, e.Status())
	}
}

func TestFailedEndpointPromotionRestoresLocalDataplaneOnce(t *testing.T) {
	e := promotionEngine(t)
	calls := 0
	e.startTunnel = func(cfg tunnel.Config) (tunnel.Session, error) {
		calls++
		if cfg.AllowlistOutbound == "tunnel" {
			return tunnel.NewFakeSession(tunnel.Info{ProviderID: tunnel.ProviderWARP, Up: false}), nil
		}
		return tunnel.NewFakeSession(tunnel.Info{ProviderID: tunnel.ProviderDesync, Up: true}), nil
	}
	e.promoteEndpointTunnelSession(e.sessionGeneration, "updates.discord.com")
	e.promoteEndpointTunnelSession(e.sessionGeneration, "updates.discord.com")
	if calls != 2 || !e.tun.Info().Up || e.tun.ProviderID() != tunnel.ProviderDesync || e.pathError == nil || e.Status().State != StateDegraded {
		t.Fatalf("rollback/retry guard failed: calls=%d status=%+v", calls, e.Status())
	}
}

func TestEndpointPromotionCannotAdoptAfterStop(t *testing.T) {
	e := promotionEngine(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	late := tunnel.NewFakeSession(tunnel.Info{ProviderID: tunnel.ProviderWARP, Up: true})
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) { close(entered); <-release; return late, nil }
	generation := e.sessionGeneration
	go func() { defer close(done); e.promoteEndpointTunnelSession(generation, "updates.discord.com") }()
	finish := sync.OnceFunc(func() { close(release); <-done })
	defer finish()
	awaitBackground(t, entered)
	if _, err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	finish()
	if !late.Closed() || e.Status().State != StateStopped {
		t.Fatal("provider outlived canceled protection")
	}
}

func TestEndpointPromotionKeepsIndependentTargetFailure(t *testing.T) {
	e := promotionEngine(t)
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) {
		e.mu.Lock()
		e.targets = append(e.targets, ipc.TargetStatus{ID: "imvu", Label: "IMVU", Path: policy.PathTunnel, Outcome: "retry"})
		e.mu.Unlock()
		return tunnel.NewFakeSession(tunnel.Info{ProviderID: tunnel.ProviderWARP, Up: true}), nil
	}
	e.promoteEndpointTunnelSession(e.sessionGeneration, "updates.discord.com")
	if e.pathError == nil || e.Status().State != StateDegraded {
		t.Fatal("Discord success cleared independent target failure")
	}
}

func TestRecoveredDiscordDoesNotPromoteForIndependentFailure(t *testing.T) {
	e := promotionEngine(t)
	e.targets[0].Path, e.targets[0].Outcome = policy.PathDesync, "ok"
	e.targets = append(e.targets, ipc.TargetStatus{ID: "imvu", Path: policy.PathTunnel, Outcome: "retry"})
	e.startTunnel = func(tunnel.Config) (tunnel.Session, error) {
		t.Fatal("healthy Discord promoted for IMVU failure")
		return nil, nil
	}
	e.promoteEndpointTunnelSession(e.sessionGeneration, "updates.discord.com")
	if e.endpointTunnelTried || e.tun.(*tunnel.FakeSession).Closed() {
		t.Fatal("healthy dataplane was disturbed")
	}
}
