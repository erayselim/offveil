package repair

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClearLearnedState(t *testing.T) {
	desyncDir := t.TempDir()
	policyDir := t.TempDir()
	t.Setenv("OFFVEIL_DESYNC_CACHE", desyncDir)
	t.Setenv("OFFVEIL_POLICY_CACHE", policyDir)

	desyncFile := filepath.Join(desyncDir, "desync-strategies.json")
	policyFile := filepath.Join(policyDir, "asn-paths.json")
	if err := os.WriteFile(desyncFile, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyFile, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ClearLearnedState(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(desyncFile); !os.IsNotExist(err) {
		t.Fatal("desync cache still present")
	}
	if _, err := os.Stat(policyFile); !os.IsNotExist(err) {
		t.Fatal("policy cache still present")
	}
}
