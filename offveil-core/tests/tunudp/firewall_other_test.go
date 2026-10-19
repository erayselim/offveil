//go:build !windows && with_gvisor

package tunudp_test

import "testing"

func assertNoFirewallSideEffects(t *testing.T) { t.Helper() }
