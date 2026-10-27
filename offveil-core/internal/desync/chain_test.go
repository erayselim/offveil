package desync

import (
	"context"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
)

func TestPassThroughFirstKeepsGlobalsAndAddsEmptyGroup(t *testing.T) {
	s := Strategy{ID: "x", Args: []string{"--no-domain", "--timeout", "3", "--split", "1", "--auto", "torst", "--tlsrec", "1+s"}}
	got := PassThroughFirst(s)
	want := []string{"--no-domain", "--timeout", "3", "--auto", "torst,ssl_err", "--split", "1", "--auto", "torst", "--tlsrec", "1+s"}
	if !reflect.DeepEqual(got.Args, want) || got.ID != "x+pass" || !IsPassThrough(got) || BaseID(got.ID) != "x" {
		t.Fatalf("chain: %+v", got)
	}
	if again := PassThroughFirst(got); !reflect.DeepEqual(again, got) {
		t.Fatalf("not idempotent: %+v", again)
	}
	if only := PassThroughFirst(Strategy{ID: "g", Args: []string{"--no-domain"}}); only.ID != "g" {
		t.Fatalf("strategy without groups must stay as is: %+v", only)
	}
}

func TestValidateStrategyArgsRejectsUnsafeFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--ip", "0.0.0.0"}, {"--port", "1"}, {"--conn-ip", "1.2.3.4"}, {"--pidfile", "x"},
		{"--fake-data", "x"}, {"--hosts", "list"}, {"--cache-dump", "-"}, {"--split"},
		{"--split", "1;rm"}, {"--no-domain=1"}, {"-D"}, {"--transparent"},
	} {
		if err := ValidateStrategyArgs(args, "windows"); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, args := range [][]string{
		{"--disorder", "1", "--fake", "-1", "--ttl", "4", "--fake-tls-mod", "rand"},
		{"--split=1+s", "--oob", "3+s"}, {"--auto", "torst,ssl_err", "--tlsrec", "0+sm"},
	} {
		if err := ValidateStrategyArgs(args, "windows"); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if err := ValidateStrategyArgs([]string{"--fake", "-1", "--ttl", "4"}, "darwin"); err == nil {
		t.Fatal("TTL strategy accepted on darwin")
	}
}

func TestBundledRulesetCandidatesAreValid(t *testing.T) {
	specs := ruleset.MustLoadEmbedded().Doc.Strategies
	got, errs := CandidatesFrom(specs)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	for _, s := range got {
		if s.Args[0] != "--no-domain" {
			t.Fatalf("%s lacks --no-domain", s.ID)
		}
		if runtime.GOOS != "darwin" && !hasFlag(s.Args, "--timeout") {
			t.Fatalf("%s lacks timeout", s.ID)
		}
	}
	merged := MergeCandidates(NativeScanCandidates(), got, NativeScanCandidates())
	if len(merged) != len(NativeScanCandidates())+len(got) {
		t.Fatalf("merge kept duplicates: %d", len(merged))
	}
}

func TestNativeSidecarAcceptsDeployedChains(t *testing.T) {
	bin := os.Getenv("OFFVEIL_BYEDPI_TEST")
	if bin == "" {
		t.Skip("set OFFVEIL_BYEDPI_TEST to the pinned ByeDPI binary")
	}
	extra, errs := CandidatesFrom(ruleset.MustLoadEmbedded().Doc.Strategies)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if err := ValidateNativeArguments(context.Background(), bin, extra...); err != nil {
		t.Fatal(err)
	}
}
