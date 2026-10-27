package engine

// Compare against the identity bound at startup, not the last metadata lookup.
// That lookup may already have adopted a changed fingerprint before heal runs.
func (e *Engine) physicalNetworkChangedLocked(next string) bool {
	known := func(fp string) bool { return fp != "" && fp != "offline" && fp != "unknown" }
	return known(e.networkFingerprint) && known(next) && e.networkFingerprint != next
}
