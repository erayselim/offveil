package desync_test

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
)

func TestDefaultSafeStrategyDarwinOmitsFakeTTL(t *testing.T) {
	s := desync.DefaultSafeStrategyDarwin()
	if s.ID != "byedpi:darwin-safe" {
		t.Fatalf("id=%s", s.ID)
	}
	want := []string{
		"--no-domain",
		"--timeout", "3",
		"--split", "1",
		"--disorder", "3+s",
		"--mod-http", "h,d",
		"--auto", "torst",
		"--tlsrec", "1+s",
	}
	if !reflect.DeepEqual(s.Args, want) {
		t.Fatalf("args=%v want %v", s.Args, want)
	}
	for _, forbid := range []string{"--fake", "--ttl"} {
		if containsArg(s.Args, forbid) {
			t.Fatalf("darwin strategy must not contain %s: %s", forbid, strings.Join(s.Args, " "))
		}
	}
	win := strings.Join(desync.DefaultSafeStrategy().Args, " ")
	if !strings.Contains(win, "--fake") || !strings.Contains(win, "--ttl") {
		t.Fatal("windows DefaultSafeStrategy lost fake/ttl")
	}
}

func TestScanCandidatesDarwinOmitsFakeTTL(t *testing.T) {
	cands := desync.ScanCandidatesDarwin()
	if len(cands) < 4 {
		t.Fatalf("expected >=4 darwin candidates, got %d", len(cands))
	}
	if cands[0].ID != desync.DefaultSafeStrategyDarwin().ID {
		t.Fatalf("first=%s", cands[0].ID)
	}
	hasOOB := false
	for _, s := range cands {
		if containsArg(s.Args, "--fake") || containsArg(s.Args, "--ttl") {
			t.Fatalf("%s has fake/ttl: %v", s.ID, s.Args)
		}
		if containsArg(s.Args, "--oob") {
			hasOOB = true
		}
	}
	if !hasOOB {
		t.Fatal("expected --oob fallback in darwin scan list")
	}

	winHasFake := false
	for _, s := range desync.ScanCandidates() {
		if containsArg(s.Args, "--fake") {
			winHasFake = true
		}
	}
	if !winHasFake {
		t.Fatal("windows ScanCandidates lost fake candidates")
	}
}

func TestNativeSafeStrategy(t *testing.T) {
	s := desync.NativeSafeStrategy()
	if runtime.GOOS == "darwin" {
		if s.ID != desync.DefaultSafeStrategyDarwin().ID {
			t.Fatalf("id=%s", s.ID)
		}
		if desync.ContainsFakeOrTTL(s.Args) {
			t.Fatalf("native darwin leaked fake/ttl: %v", s.Args)
		}
	} else if s.ID != desync.DefaultSafeStrategy().ID {
		t.Fatalf("id=%s", s.ID)
	}
}

func TestNativeScanCandidates(t *testing.T) {
	cands := desync.NativeScanCandidates()
	if len(cands) == 0 {
		t.Fatal("empty")
	}
	if cands[0].ID != desync.NativeSafeStrategy().ID {
		t.Fatalf("first=%s", cands[0].ID)
	}
	if runtime.GOOS == "darwin" {
		hasOOB := false
		for _, s := range cands {
			if desync.ContainsFakeOrTTL(s.Args) {
				t.Fatalf("%s has fake/ttl", s.ID)
			}
			if containsArg(s.Args, "--oob") {
				hasOOB = true
			}
		}
		if !hasOOB {
			t.Fatal("darwin scan needs --oob")
		}
	}
}

func TestUsableOnOSRejectsFakeOnDarwin(t *testing.T) {
	win := desync.DefaultSafeStrategy()
	dar := desync.DefaultSafeStrategyDarwin()
	if !desync.UsableOnOS(dar) {
		t.Fatal("darwin-safe must be usable")
	}
	if runtime.GOOS == "darwin" {
		if desync.UsableOnOS(win) {
			t.Fatal("windows fake/ttl must not be usable on darwin")
		}
	} else if !desync.UsableOnOS(win) {
		t.Fatal("windows-safe must be usable on windows")
	}
}

func TestStrategyByIDDarwinOOB(t *testing.T) {
	s, ok := desync.StrategyByID("byedpi:oob")
	if !ok || !containsArg(s.Args, "--oob") {
		t.Fatalf("oob=%+v ok=%v", s, ok)
	}
	s, ok = desync.StrategyByID("byedpi:darwin-safe")
	if !ok || s.ID != "byedpi:darwin-safe" {
		t.Fatalf("darwin-safe=%+v ok=%v", s, ok)
	}
}

func containsArg(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}
