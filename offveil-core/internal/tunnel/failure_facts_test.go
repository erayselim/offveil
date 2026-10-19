package tunnel

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

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
