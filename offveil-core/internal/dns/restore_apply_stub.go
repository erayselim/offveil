//go:build !windows && !darwin

package dns

// RestoreLeftoverDNS is Windows leak-guard / Darwin networksetup.
func RestoreLeftoverDNS(bool) (string, error) {
	return "skipped", nil
}
