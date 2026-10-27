package diag

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDiagnosticsDirectoryIsReadableDespiteUmask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	dir := filepath.Join(t.TempDir(), "diagnostics")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OFFVEIL_DIAG_DIR", dir)
	if err := RecordFailure(Failure{Component: "engine", Event: "fixture"}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("mode=%v err=%v", st.Mode().Perm(), err)
	}
}
