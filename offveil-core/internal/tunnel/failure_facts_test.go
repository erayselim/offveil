package tunnel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDataplaneLaunchesOwnDistinctConfigsAndCleanOnlyTheirOwnFile(t *testing.T) {
	cfg := Config{DataDir: t.TempDir(), AllowlistOutbound: "desync", SkipStart: true}
	first, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	a, b := first.Info().ConfigPath, second.Info().ConfigPath
	if a == "" || b == "" || a == b {
		t.Fatal("overlapping launches share a mutable configuration")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a); !os.IsNotExist(err) {
		t.Fatalf("first config not removed: %v", err)
	}
	if _, err := os.Stat(b); err != nil {
		t.Fatalf("old session removed replacement config: %v", err)
	}
}

func TestExhaustedProviderRetainsFailureFacts(t *testing.T) {
	noFailover := false
	dir := t.TempDir()
	sess, err := Start(Config{
		DataDir: dir, BinaryPath: filepath.Join(dir, "missing-sidecar"),
		Failover: &noFailover,
		Reality:  &RealityCredentials{Server: "test.invalid", UUID: "test-id", PublicKey: "test-key"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	info := sess.Info()
	if info.Up || !info.RetryHint || len(info.Failures) != 1 || info.Failures[0].ProviderID != ProviderReality || info.Failures[0].Class != FailDial {
		t.Fatalf("missing provider failure facts: %+v", info)
	}
}

func TestSuccessfulProbeClearsPreviousRetryHint(t *testing.T) {
	s := softFailSession(Config{}, ProviderDesync, FailTimeout, context.DeadlineExceeded, nil, "")
	s.recordProbe(FailSignal{Class: FailTimeout, Detail: "timed out", At: time.Now()})
	s.recordProbe(FailSignal{Class: FailOK, At: time.Now()})
	if info := s.Info(); info.RetryHint || info.FailDetail != "" || info.LastProbe != FailOK {
		t.Fatalf("successful TLS left the UI broken: %+v", info)
	}
}
