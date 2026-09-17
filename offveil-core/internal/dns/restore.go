package dns

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/erayselim/offveil/offveil-core/internal/appdir"
)

const restoreSnapshotVer = 1

// RestoreSnapshot is the on-disk leak-guard undo record.
// Written before DNS is rewritten so a crash can still restore the NIC
// (Windows) or networksetup services (Darwin).
type RestoreSnapshot struct {
	Version int         `json:"version"`
	StubIP  string      `json:"stub_ip,omitempty"`
	Tun     *RestoreNIC `json:"tun,omitempty"`
	Egress  *RestoreNIC `json:"egress,omitempty"`
	// Services is Darwin networksetup undo (Wi-Fi / Ethernet / Thunderbolt).
	// Windows ignore this field.
	Services []ServiceDNS `json:"services,omitempty"`
}

// RestoreNIC is one adapter's previous IPv4 DNS servers.
type RestoreNIC struct {
	LUID uint64   `json:"luid"`
	DNS  []string `json:"dns"`
}

// ServiceDNS is one Darwin networksetup service's previous DNS servers.
// DHCP true (or empty DNS) restores with `empty` so DHCP takes over again.
type ServiceDNS struct {
	Name string   `json:"name"`
	DNS  []string `json:"dns,omitempty"`
	DHCP bool     `json:"dhcp,omitempty"`
}

// DefaultRestorePath is <appdir>/dns-restore.json (or OFFVEIL_DNS_RESTORE).
func DefaultRestorePath() string {
	if p := os.Getenv("OFFVEIL_DNS_RESTORE"); p != "" {
		return p
	}
	return filepath.Join(appdir.Root(), "dns-restore.json")
}

// SaveRestoreSnapshot writes the leak-guard undo file (best-effort callers ignore error).
func SaveRestoreSnapshot(snap RestoreSnapshot) error {
	snap.Version = restoreSnapshotVer
	path := DefaultRestorePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadRestoreSnapshot reads the undo file. nil, nil when absent.
func LoadRestoreSnapshot() (*RestoreSnapshot, error) {
	path := DefaultRestorePath()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	var snap RestoreSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// ClearRestoreSnapshot deletes the undo file. Missing is OK.
func ClearRestoreSnapshot() error {
	err := os.Remove(DefaultRestorePath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
