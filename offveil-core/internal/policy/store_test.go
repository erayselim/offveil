package policy_test

import (
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
	"github.com/erayselim/offveil/offveil-core/internal/policy"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

func TestDesyncFailMapsToTunnel(t *testing.T) {
	s := policy.NewStore()
	s.OnDesyncFail(desync.FailSignal{
		Target:     "discord.com",
		Class:      desync.FailReset,
		StrategyID: "byedpi:windows-safe",
		At:         time.Now().UTC(),
	})
	e, ok := s.Lookup("discord.com")
	if !ok {
		t.Fatal("missing entry")
	}
	if e.Path != policy.PathTunnel {
		t.Fatalf("path=%s", e.Path)
	}
	if e.Class != "dpi_reset" {
		t.Fatalf("class=%s", e.Class)
	}
	if s.HintFor("discord.com") != policy.PathTunnel {
		t.Fatal("hint")
	}
	if e.Key != "asn:unknown|discord.com" {
		t.Fatalf("key=%s", e.Key)
	}
}

func TestDesyncOKMapsToDesync(t *testing.T) {
	s := policy.NewStore()
	s.OnDesyncOK("discord.com", "byedpi:windows-safe")
	e, ok := s.Lookup("discord.com")
	if !ok || e.Path != policy.PathDesync {
		t.Fatalf("%v %v", ok, e)
	}
}

func TestTunnelFailMapsToRetry(t *testing.T) {
	s := policy.NewStore()
	s.OnTunnelFail(tunnel.FailSignal{
		Target:     "discord.com",
		Class:      tunnel.FailAuth,
		ProviderID: "warp",
		At:         time.Now().UTC(),
	})
	e, ok := s.Lookup("discord.com")
	if !ok || e.Path != policy.PathTunnel || e.Class != "retry" {
		t.Fatalf("%v %+v", ok, e)
	}
}

func TestASNChangeInvalidates(t *testing.T) {
	s := policy.NewStore()
	s.ObserveNetwork(netinfo.Info{ASN: "9121", Fingerprint: "aaa", ISPHint: "TT"})
	s.Put("discord.com", policy.PathDesync, "dpi_reset", "probe")
	if _, ok := s.Lookup("discord.com"); !ok {
		t.Fatal("missing")
	}
	inv := s.ObserveNetwork(netinfo.Info{ASN: "34984", Fingerprint: "aaa", ISPHint: "TTNet"})
	if !inv {
		t.Fatal("expected invalidate on ASN change")
	}
	if _, ok := s.Lookup("discord.com"); ok {
		t.Fatal("cache should be empty")
	}
	if s.ASN() != "34984" {
		t.Fatalf("asn=%s", s.ASN())
	}
}

func TestFingerprintChangeInvalidates(t *testing.T) {
	s := policy.NewStore()
	s.ObserveNetwork(netinfo.Info{ASN: "9121", Fingerprint: "fp1"})
	s.Put("discord.com", policy.PathDirect, "open", "probe")
	if !s.ObserveNetwork(netinfo.Info{ASN: "9121", Fingerprint: "fp2"}) {
		t.Fatal("expected invalidate on fingerprint change")
	}
	if _, ok := s.Lookup("discord.com"); ok {
		t.Fatal("expected empty")
	}
}

func TestPutUsesASNKey(t *testing.T) {
	s := policy.NewStore()
	s.ObserveNetwork(netinfo.Info{ASN: "AS9121", Fingerprint: "x"})
	s.Put("discord.com", policy.PathTunnel, "ip_drop", "probe")
	e, ok := s.Lookup("discord.com")
	if !ok || e.Key != "asn:9121|discord.com" {
		t.Fatalf("%v %+v", ok, e)
	}
}

func TestTTLForClasses(t *testing.T) {
	if policy.TTLFor(policy.PathDirect, "open") != 24*time.Hour {
		t.Fatal("direct open")
	}
	if policy.TTLFor(policy.PathTunnel, "retry") != 15*time.Minute {
		t.Fatal("retry")
	}
	if policy.TTLFor(policy.PathDesync, "dpi_reset") != 6*time.Hour {
		t.Fatal("dpi")
	}
}

func TestExpiredDomains(t *testing.T) {
	s := policy.NewStore()
	s.PutWithTTL("discord.com", policy.PathDesync, "dpi_reset", "probe", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	got := s.ExpiredDomains()
	if len(got) != 1 || got[0] != "discord.com" {
		t.Fatalf("%v", got)
	}
	if _, ok := s.Lookup("discord.com"); ok {
		t.Fatal("should be gone")
	}
}
