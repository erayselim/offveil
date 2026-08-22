package desync_test

import (
	"strings"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
)

func TestDefaultSafeStrategy(t *testing.T) {
	s := desync.DefaultSafeStrategy()
	if s.ID != "byedpi:windows-safe" {
		t.Fatalf("id=%s", s.ID)
	}
	joined := strings.Join(s.Args, " ")
	for _, need := range []string{"--no-domain", "--split", "--disorder", "--auto", "torst", "ssl_err", "--tlsrec", "--fake"} {
		if !strings.Contains(joined, need) {
			t.Fatalf("strategy missing %q in %s", need, joined)
		}
	}
}

func TestSafeStrategySet(t *testing.T) {
	set := desync.SafeStrategySet()
	if len(set) < 3 {
		t.Fatalf("expected >=3 named groups, got %d", len(set))
	}
}

func TestStrategyByID(t *testing.T) {
	s, ok := desync.StrategyByID("byedpi:disorder-fake")
	if !ok || len(s.Args) == 0 {
		t.Fatalf("StrategyByID: %+v ok=%v", s, ok)
	}
}

func TestBuildArgs(t *testing.T) {
	s := desync.DefaultSafeStrategy()
	args := desync.BuildArgs("127.0.0.1", 18080, s)
	if args[0] != "--ip" || args[1] != "127.0.0.1" {
		t.Fatalf("args=%v", args)
	}
	if args[2] != "--port" || args[3] != "18080" {
		t.Fatalf("args=%v", args)
	}
	if !desync.UDPEnabled(args) {
		t.Fatal("Discord voice requires UDP ASSOCIATE (no --no-udp)")
	}
}

func TestBuildArgsStripsNoUDP(t *testing.T) {
	s := desync.Strategy{
		ID:   "bad",
		Args: []string{"--no-domain", "--no-udp", "-U", "--split", "1"},
	}
	args := desync.BuildArgs("127.0.0.1", 18080, s)
	if !desync.UDPEnabled(args) {
		t.Fatalf("expected --no-udp stripped: %v", args)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--no-udp") || strings.Contains(joined, "-U") {
		t.Fatalf("still has no-udp: %v", args)
	}
}
