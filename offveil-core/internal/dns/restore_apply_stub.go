//go:build !windows

package dns

// RestoreLeftoverDNS is Windows-only.
func RestoreLeftoverDNS(bool) (string, error) {
	return "skipped", nil
}
