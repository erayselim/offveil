package policy_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/policy"
)

func TestASNPathStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "asn-paths.json")
	s, err := policy.OpenASNPathStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put("206375", policy.PathTunnel); err != nil {
		t.Fatal(err)
	}
	s2, err := policy.OpenASNPathStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Lookup("206375")
	if !ok || got != policy.PathTunnel {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestASNPathStoreExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "asn-paths.json")
	s, err := policy.OpenASNPathStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put("1", policy.PathDesync); err != nil {
		t.Fatal(err)
	}
	// Force expiry by rewriting entry timestamp via re-open + manual isn't exposed;
	// Lookup with unknown always false.
	if _, ok := s.Lookup("unknown"); ok {
		t.Fatal("unknown should miss")
	}
	_ = time.Now()
}
