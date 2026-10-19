//go:build windows && with_gvisor

package tunudp_test

import (
	"testing"

	tun "github.com/sagernet/sing-tun"
)

func assertNoFirewallSideEffects(t *testing.T) {
	t.Helper()
	// This symbol exists only in the staged test fixture. Running without the
	// wrapper fails at compile time instead of adding a Windows firewall rule.
	if !tun.OffveilTestFirewallStubActive() {
		t.Fatal("firewall test fixture missing")
	}
}
