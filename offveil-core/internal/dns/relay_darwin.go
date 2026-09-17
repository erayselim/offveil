//go:build darwin

package dns

import "os/exec"

// RelayDiagNotes records Private Relay / Limit IP tracking. Never disables them.
func RelayDiagNotes() []string {
	out, err := exec.Command("/usr/sbin/scutil", "--dns").CombinedOutput()
	if err != nil {
		return []string{"icloud_private_relay: unknown"}
	}
	return []string{RelayDiagNote(PrivateRelayFromScutil(string(out)))}
}
