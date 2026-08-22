package crashlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWritePanic(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFVEIL_LOG_DIR", dir)
	WritePanic("test-boom")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("want 1 log, got %d", len(ents))
	}
	b, err := os.ReadFile(filepath.Join(dir, ents[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "test-boom") {
		t.Fatalf("missing panic text: %s", b)
	}
}
