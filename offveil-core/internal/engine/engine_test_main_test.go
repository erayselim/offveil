package engine_test

import (
	"os"
	"path/filepath"
	"testing"
)

// Isolate ASN path cache from the developer machine's ProgramData between tests.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "offveil-engine-policy-*")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("OFFVEIL_POLICY_CACHE", dir)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// uniquePolicyCache forces a fresh ASN path file for tests that share ASN 9121.
func uniquePolicyCache(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("OFFVEIL_POLICY_CACHE", dir)
	// Ensure subdirectory exists for OpenASNPathStore.
	_ = os.MkdirAll(filepath.Join(dir), 0o755)
}
