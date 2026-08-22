package ipc

import "testing"

func TestAllowedMethod(t *testing.T) {
	ok := []string{"ping", "health", "status", "start", "stop", "restart", "shutdown", "test", "diagnostics", "repair"}
	for _, m := range ok {
		if !AllowedMethod(m) {
			t.Fatalf("want allow %q", m)
		}
	}
	if AllowedMethod("eval") || AllowedMethod("") || AllowedMethod("Start") {
		t.Fatal("unexpected allow")
	}
}
