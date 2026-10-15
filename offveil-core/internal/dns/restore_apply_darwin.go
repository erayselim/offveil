//go:build darwin

package dns

// RestoreLeftoverDNS restores recorded networksetup settings, retaining failed
// services for retry. Without a record, only an armed cleanup may clear the
// default offveil address. Original local resolvers are preserved.
func RestoreLeftoverDNS(armed bool) (string, error) {
	return restoreSystemDNSWith(liveSystemDNS(), armed, localResolverListening())
}
