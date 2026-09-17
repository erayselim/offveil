//go:build darwin

package dns

// RestoreLeftoverDNS undoes networksetup 127.0.0.1 leftovers using
// dns-restore.json, then empties any remaining loopback DNS when the stub
// is down. Flush is killall -HUP mDNSResponder.
func RestoreLeftoverDNS(armed bool) (string, error) {
	return restoreSystemDNSWith(liveSystemDNS(), armed, localResolverListening())
}
