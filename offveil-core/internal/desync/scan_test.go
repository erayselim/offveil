package desync_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
)

type hostTrialSession struct {
	*desync.FakeSession
	check func(string) desync.FailSignal
}

func (s *hostTrialSession) ProbeTLS(host string) desync.FailSignal { return s.check(host) }

func TestScanRejectsStrategyThatBreaksAnAlreadyWorkingTarget(t *testing.T) {
	var mu sync.Mutex
	var trials []*desync.FakeSession
	var hosts []string
	res := desync.Scan(context.Background(), desync.ScanConfig{
		Host: "secure.imvu.com", VerifyHosts: []string{"discord.com", "secure.imvu.com"},
		Concurrency: 1,
		ConnIP:      "192.0.2.10", BindInterface: "Wi-Fi",
		Candidates: []desync.Strategy{
			{ID: "imvu-only", Args: []string{"--split", "1"}},
			{ID: "both", Args: []string{"--split", "2"}},
		},
		Start: func(cfg desync.Config) (desync.Session, error) {
			if cfg.Context == nil || cfg.Sink != nil || cfg.ProbeHost != "" ||
				cfg.ConnIP != "192.0.2.10" || cfg.BindInterface != "Wi-Fi" || cfg.ListenPort == 18080 {
				t.Fatalf("trial config lost isolation/egress: %+v", cfg)
			}
			base := desync.NewFakeSession(desync.Info{StrategyID: cfg.Strategy.ID})
			mu.Lock()
			trials = append(trials, base)
			mu.Unlock()
			return &hostTrialSession{base, func(host string) desync.FailSignal {
				mu.Lock()
				hosts = append(hosts, host)
				mu.Unlock()
				class := desync.FailOK
				if cfg.Strategy.ID == "imvu-only" && host == "discord.com" {
					class = desync.FailReset
				}
				return desync.FailSignal{Target: host, Class: class}
			}}, nil
		},
	})
	if !res.OK || res.Strategy.ID != "both" || len(res.Tried) != 2 || len(hosts) != 4 || len(res.Tried[0].Checks) != 2 {
		t.Fatalf("single-target winner accepted: %+v hosts=%v", res, hosts)
	}
	for _, trial := range trials {
		if !trial.Closed() {
			t.Fatal("trial helper left running")
		}
	}
}

func TestScanSlowFirstCandidateCannotStarveWorkingAlternative(t *testing.T) {
	blocked := make(chan struct{})
	var active, peak atomic.Int32
	var trials sync.Map
	res := desync.Scan(context.Background(), desync.ScanConfig{
		Host: "discord.com", Timeout: time.Second, PerStrategy: time.Second,
		Candidates: []desync.Strategy{{ID: "slow", Args: []string{"--split", "1"}}, {ID: "works", Args: []string{"--tlsrec", "1+s"}}},
		Start: func(cfg desync.Config) (desync.Session, error) {
			n := active.Add(1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			base := desync.NewFakeSession(desync.Info{StrategyID: cfg.Strategy.ID})
			trials.Store(cfg.Strategy.ID, base)
			return &hostTrialSession{base, func(host string) desync.FailSignal {
				defer active.Add(-1)
				if cfg.Strategy.ID == "slow" {
					close(blocked)
					<-cfg.Context.Done()
					return desync.FailSignal{Target: host, Class: desync.FailTimeout}
				}
				<-blocked
				return desync.FailSignal{Target: host, Class: desync.FailOK}
			}}, nil
		},
	})
	if !res.OK || res.Strategy.ID != "works" || peak.Load() != 2 || active.Load() != 0 {
		t.Fatalf("alternative was starved or worker leaked: %+v peak=%d active=%d", res, peak.Load(), active.Load())
	}
	trials.Range(func(_, value any) bool {
		if !value.(*desync.FakeSession).Closed() {
			t.Error("trial leaked")
		}
		return true
	})
}

func TestScanSharesDeadlineAcrossConcurrentTargetChecks(t *testing.T) {
	var entered atomic.Int32
	all := make(chan struct{})
	res := desync.Scan(context.Background(), desync.ScanConfig{
		Host: "discord.com", VerifyHosts: []string{"updates.discord.com", "gateway.discord.gg"},
		Timeout: time.Second, PerStrategy: time.Second,
		Candidates: []desync.Strategy{{ID: "all", Args: []string{"--split", "1"}}},
		Start: func(cfg desync.Config) (desync.Session, error) {
			return &hostTrialSession{desync.NewFakeSession(desync.Info{}), func(host string) desync.FailSignal {
				if entered.Add(1) == 3 {
					close(all)
				}
				select {
				case <-all:
					return desync.FailSignal{Target: host, Class: desync.FailOK}
				case <-cfg.Context.Done():
					return desync.FailSignal{Target: host, Class: desync.FailTimeout}
				}
			}}, nil
		},
	})
	if !res.OK || len(res.Tried[0].Checks) != 3 {
		t.Fatalf("targets serialized or omitted: %+v", res)
	}
}

func TestScanCancellationRejectsLateSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := desync.NewFakeSession(desync.Info{})
	res := desync.Scan(ctx, desync.ScanConfig{
		Host: "discord.com", Candidates: []desync.Strategy{{ID: "late", Args: []string{"--split", "1"}}},
		Start: func(cfg desync.Config) (desync.Session, error) {
			return &hostTrialSession{base, func(host string) desync.FailSignal {
				cancel()
				return desync.FailSignal{Target: host, Class: desync.FailOK}
			}}, nil
		},
	})
	if res.OK || !base.Closed() {
		t.Fatal("cancelled trial won or leaked its process")
	}
}

func TestScanBoundsStartupWithParentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	began := time.Now()
	res := desync.Scan(ctx, desync.ScanConfig{
		Timeout: time.Minute, PerStrategy: time.Minute,
		Candidates: []desync.Strategy{{ID: "blocked", Args: []string{"--split", "1"}}},
		Start: func(cfg desync.Config) (desync.Session, error) {
			<-cfg.Context.Done()
			return nil, errors.New("cancelled startup")
		},
	})
	if res.OK || time.Since(began) > time.Second {
		t.Fatal("startup ignored the caller's total scan deadline")
	}
}

func TestScanCandidates(t *testing.T) {
	cands := desync.ScanCandidates()
	if len(cands) < 4 {
		t.Fatalf("expected >=4 candidates, got %d", len(cands))
	}
	if cands[0].ID != desync.DefaultSafeStrategy().ID {
		t.Fatalf("first candidate should be default safe, got %s", cands[0].ID)
	}
	for _, c := range cands {
		if c.ID == "" || len(c.Args) == 0 {
			t.Fatalf("invalid candidate: %+v", c)
		}
	}
}

func TestScanFindsWorkingStrategy(t *testing.T) {
	want := "byedpi:disorder-fake"
	start := func(cfg desync.Config) (desync.Session, error) {
		class := desync.FailReset
		if cfg.Strategy.ID == want {
			class = desync.FailOK
		}
		return &probeClassSession{
			FakeSession: desync.NewFakeSession(desync.Info{
				StrategyID: cfg.Strategy.ID,
				LastProbe:  class,
			}),
			class: class,
		}, nil
	}

	res := desync.Scan(context.Background(), desync.ScanConfig{
		Host:        "discord.com",
		Concurrency: 1,
		Timeout:     5 * time.Second,
		PerStrategy: 500 * time.Millisecond,
		Start:       start,
		Candidates: []desync.Strategy{
			{ID: "byedpi:windows-safe", Args: []string{"--no-domain"}},
			{ID: "byedpi:split-disorder", Args: []string{"--no-domain"}},
			{ID: want, Args: []string{"--no-domain", "--fake", "-1"}},
		},
	})
	if !res.OK {
		t.Fatalf("expected OK, got %+v", res)
	}
	if res.Strategy.ID != want {
		t.Fatalf("strategy=%s want %s (tried=%v)", res.Strategy.ID, want, res.Tried)
	}
	if len(res.Tried) < 3 {
		t.Fatalf("expected to try failed ones first, tried=%v", res.Tried)
	}
}

func TestScanTimeout(t *testing.T) {
	start := func(cfg desync.Config) (desync.Session, error) {
		return &slowFailSession{id: cfg.Strategy.ID}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	res := desync.Scan(ctx, desync.ScanConfig{
		Host:        "discord.com",
		Timeout:     80 * time.Millisecond,
		PerStrategy: 50 * time.Millisecond,
		Start:       start,
		Candidates: []desync.Strategy{
			{ID: "a", Args: []string{"--x"}},
			{ID: "b", Args: []string{"--y"}},
			{ID: "c", Args: []string{"--z"}},
		},
	})
	if res.OK {
		t.Fatalf("expected fail on timeout, got %+v", res)
	}
}

func TestStrategyStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "desync-strategies.json")
	store, err := desync.OpenStrategyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Lookup("9121"); ok {
		t.Fatal("expected empty")
	}
	s := desync.Strategy{
		ID:   "byedpi:disorder-fake",
		Args: []string{"--no-domain", "--fake", "-1"},
	}
	if err := store.Put("9121", s, "discord.com"); err != nil {
		t.Fatal(err)
	}
	got, ok := store.Lookup("9121")
	if !ok || got.ID != s.ID || len(got.Args) != len(s.Args) {
		t.Fatalf("lookup=%v ok=%v", got, ok)
	}

	store2, err := desync.OpenStrategyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got2, ok := store2.Lookup("9121")
	if !ok || got2.ID != s.ID {
		t.Fatalf("reload lookup=%v ok=%v", got2, ok)
	}
	if err := store2.Delete("9121"); err != nil {
		t.Fatal(err)
	}
	if _, ok := store2.Lookup("9121"); ok {
		t.Fatal("expected deleted")
	}
}

type probeClassSession struct {
	*desync.FakeSession
	class desync.FailClass
}

func (p *probeClassSession) ProbeTLS(host string) desync.FailSignal {
	return desync.FailSignal{Target: host, Class: p.class, StrategyID: p.StrategyID()}
}

type slowFailSession struct {
	id string
}

func (s *slowFailSession) Info() desync.Info {
	return desync.Info{StrategyID: s.id, Up: true, LastProbe: desync.FailTimeout}
}
func (s *slowFailSession) SocksAddr() string  { return "127.0.0.1:0" }
func (s *slowFailSession) StrategyID() string { return s.id }
func (s *slowFailSession) ProbeTLS(host string) desync.FailSignal {
	time.Sleep(40 * time.Millisecond)
	return desync.FailSignal{Target: host, Class: desync.FailTimeout, StrategyID: s.id}
}
func (s *slowFailSession) Close() error { return nil }
