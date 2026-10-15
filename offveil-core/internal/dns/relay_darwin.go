//go:build darwin

package dns

import (
	"context"
	"os/exec"
	"time"
)

// RelayDiagNotes records Private Relay / Limit IP tracking. Never disables them.
func RelayDiagNotes() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns").CombinedOutput()
	if err != nil {
		return []string{"icloud_private_relay: unknown"}
	}
	return []string{RelayDiagNote(PrivateRelayFromScutil(string(out)))}
}
