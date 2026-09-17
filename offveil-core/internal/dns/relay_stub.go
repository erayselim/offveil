//go:build !darwin

package dns

// RelayDiagNotes is Darwin-only (scutil --dns).
func RelayDiagNotes() []string { return nil }
