package appdir

import (
	"runtime"
	"strings"
	"testing"
)

func TestRoot(t *testing.T) {
	got := Root()
	if got == "" || !strings.Contains(got, "offveil") {
		t.Fatalf("Root()=%q", got)
	}
	switch runtime.GOOS {
	case "windows":
		if strings.Contains(got, "Application Support") {
			t.Fatalf("windows Root used Darwin path: %s", got)
		}
	case "darwin":
		want := "/Library/Application Support/offveil"
		if got != want {
			t.Fatalf("Root()=%q want %q", got, want)
		}
	}
}
