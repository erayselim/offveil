//go:build !windows

package capture

import "fmt"

// Start is Windows-only.
func Start(Config) (Session, error) {
	return nil, fmt.Errorf("capture: TUN is only supported on Windows")
}

// TakeSnapshot is Windows-only.
func TakeSnapshot() (*Snapshot, error) {
	return nil, fmt.Errorf("capture: adapter snapshot is only supported on Windows")
}

// FindAdapterLUIDByName is Windows-only.
func FindAdapterLUIDByName(string) (uint64, error) {
	return 0, fmt.Errorf("capture: adapter lookup is only supported on Windows")
}

// AdapterPresent is Windows-only.
func AdapterPresent() bool { return false }

// CloseOrphanAdapter is Windows-only.
func CloseOrphanAdapter() error { return nil }
