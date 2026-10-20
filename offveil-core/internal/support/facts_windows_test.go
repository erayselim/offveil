//go:build windows

package support

import (
	"context"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsOfflineFactsAreReadOnlyAndExcludeAddresses(t *testing.T) {
	facts := map[string]any{}
	platformFacts(context.Background(), facts)
	service, ok := facts["windows_service"].(map[string]any)
	if !ok || service["state"] == nil {
		t.Fatal("SCM state absent")
	}
	adapter, ok := facts["offveil_adapter"].(map[string]any)
	if !ok || adapter["present"] == nil {
		t.Fatal("adapter presence absent")
	}
	for _, key := range []string{"addresses", "gateway", "mac", "name", "path", "account"} {
		if adapter[key] != nil || service[key] != nil {
			t.Fatalf("unexpected identifying field %s", key)
		}
	}
	if windowsServiceState(windows.SERVICE_RUNNING) != "running" || windowsServiceState(windows.SERVICE_STOPPED) != "stopped" {
		t.Fatal("SCM state mapping")
	}
}
