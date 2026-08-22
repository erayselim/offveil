package probe_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/probe"
)

func fixedResolve(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
}

func noSystemPoison(string, *offdns.PoisonSet) ([]netip.Addr, string, error) {
	return nil, "", nil
}

func TestPathFor(t *testing.T) {
	cases := map[probe.Class]string{
		probe.ClassOpen:            "direct",
		probe.ClassDPIReset:        "desync",
		probe.ClassIPDrop:          "tunnel",
		probe.ClassTimeout:         "desync",
		probe.ClassThrottleSuspect: "tunnel",
		probe.ClassDNSPoison:       "desync",
	}
	for c, want := range cases {
		if got := probe.PathFor(c); got != want {
			t.Fatalf("%s → %s want %s", c, got, want)
		}
	}
}

func TestTargetOpen(t *testing.T) {
	res := probe.Target(context.Background(), "discord.com", probe.Options{
		Timeout:      2 * time.Second,
		Resolve:      fixedResolve,
		LookupSystem: noSystemPoison,
		DialTLS:      func(context.Context, string, string) error { return nil },
	})
	if res.Class != probe.ClassOpen || res.Path != "direct" {
		t.Fatalf("%+v", res)
	}
	if !res.OK {
		t.Fatal("expected ok")
	}
}

func TestTargetDPIReset(t *testing.T) {
	res := probe.Target(context.Background(), "discord.com", probe.Options{
		Resolve:      fixedResolve,
		LookupSystem: noSystemPoison,
		DialTLS: func(context.Context, string, string) error {
			return &net.OpError{Op: "read", Err: errors.New("connection reset by peer")}
		},
	})
	if res.Class != probe.ClassDPIReset || res.Path != "desync" {
		t.Fatalf("%+v", res)
	}
}

func TestTargetIPDropOnDialTimeout(t *testing.T) {
	res := probe.Target(context.Background(), "discord.com", probe.Options{
		Resolve:      fixedResolve,
		LookupSystem: noSystemPoison,
		DialTLS: func(context.Context, string, string) error {
			return &net.OpError{Op: "dial", Err: timeoutErr{}}
		},
	})
	if res.Class != probe.ClassIPDrop || res.Path != "tunnel" {
		t.Fatalf("%+v", res)
	}
}

func TestTargetSystemPoisonThenOpen(t *testing.T) {
	res := probe.Target(context.Background(), "discord.com", probe.Options{
		Resolve: fixedResolve,
		LookupSystem: func(string, *offdns.PoisonSet) ([]netip.Addr, string, error) {
			return []netip.Addr{netip.MustParseAddr("195.175.254.2")}, "ooni.tr_6", nil
		},
		DialTLS: func(context.Context, string, string) error { return nil },
	})
	if res.Class != probe.ClassOpen || res.Path != "direct" {
		t.Fatalf("%+v", res)
	}
}

func TestTargetConnRefused(t *testing.T) {
	res := probe.Target(context.Background(), "discord.com", probe.Options{
		Resolve:      fixedResolve,
		LookupSystem: noSystemPoison,
		DialTLS: func(context.Context, string, string) error {
			return &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
		},
	})
	if res.Class != probe.ClassIPDrop {
		t.Fatalf("%+v", res)
	}
}

func TestTargetThrottle(t *testing.T) {
	res := probe.Target(context.Background(), "discord.com", probe.Options{
		Resolve:      fixedResolve,
		LookupSystem: noSystemPoison,
		DialTLS: func(context.Context, string, string) error {
			time.Sleep(probe.ThrottleThreshold + 50*time.Millisecond)
			return nil
		},
	})
	if res.Class != probe.ClassThrottleSuspect || res.Path != "tunnel" {
		t.Fatalf("%+v", res)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestCuratedAndSession(t *testing.T) {
	if h := probe.CuratedHosts(); h[0] != "discord.com" {
		t.Fatal(h)
	}
	rep := probe.Session(context.Background(), nil, probe.Options{
		Resolve:      fixedResolve,
		LookupSystem: noSystemPoison,
		DialTLS:      func(context.Context, string, string) error { return nil },
		SkipControl:  true,
	})
	if len(rep.Results) != 1 || rep.Results[0].Class != probe.ClassOpen {
		t.Fatalf("%+v", rep)
	}
	if rep.Chosen != "direct" {
		t.Fatalf("chosen=%s", rep.Chosen)
	}
}

func TestSessionControlOpenStrengthensDPI(t *testing.T) {
	rep := probe.Session(context.Background(), []string{"discord.com"}, probe.Options{
		Resolve:      fixedResolve,
		LookupSystem: noSystemPoison,
		ControlHost:  "www.microsoft.com",
		DialTLS: func(_ context.Context, _, serverName string) error {
			if serverName == "www.microsoft.com" {
				return nil
			}
			return errors.New("i/o timeout")
		},
	})
	if len(rep.Results) != 1 {
		t.Fatal(rep)
	}
	if rep.Results[0].Class != probe.ClassDPIReset {
		t.Fatalf("want dpi_reset got %+v", rep.Results[0])
	}
	if rep.Chosen != "desync" {
		t.Fatalf("chosen=%s", rep.Chosen)
	}
}

func TestMultiIPPrefersWorking(t *testing.T) {
	n := 0
	res := probe.Target(context.Background(), "discord.com", probe.Options{
		LookupSystem: noSystemPoison,
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("1.2.3.4"),
				netip.MustParseAddr("5.6.7.8"),
			}, nil
		},
		DialTLS: func(context.Context, string, string) error {
			n++
			if n == 1 {
				return &net.OpError{Op: "dial", Err: timeoutErr{}}
			}
			return nil
		},
	})
	if res.Class != probe.ClassOpen {
		t.Fatalf("%+v", res)
	}
}

func TestPreferPath(t *testing.T) {
	if probe.PreferPath("direct", "tunnel") != "tunnel" {
		t.Fatal()
	}
	if probe.PreferPath("tunnel", "desync") != "tunnel" {
		t.Fatal()
	}
}
