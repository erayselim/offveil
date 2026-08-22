package desync_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
)

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
