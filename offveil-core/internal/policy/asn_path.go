package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	asnPathStoreVer = 1
	// ASNPathTTL: trust a prior cascade path for this ISS (skip wasted desync on restart).
	ASNPathTTL = 7 * 24 * time.Hour
)

// ASNPathEntry remembers the last winning outbound path for an ISS ASN.
type ASNPathEntry struct {
	ASN       string    `json:"asn"`
	Path      string    `json:"path"` // direct | desync | tunnel
	UpdatedAt time.Time `json:"updated_at"`
}

type asnPathFile struct {
	Version int                     `json:"version"`
	Entries map[string]ASNPathEntry `json:"entries"`
}

// ASNPathStore persists ASN → cascade path across service restarts.
type ASNPathStore struct {
	mu   sync.Mutex
	path string
	data asnPathFile
}

// DefaultASNPathStorePath is ProgramData/offveil/policy/asn-paths.json.
func DefaultASNPathStorePath() (string, error) {
	if d := os.Getenv("OFFVEIL_POLICY_CACHE"); d != "" {
		return filepath.Join(d, "asn-paths.json"), nil
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "offveil", "policy", "asn-paths.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "offveil", "policy", "asn-paths.json"), nil
}

// OpenASNPathStore loads or creates the store (empty path → default).
func OpenASNPathStore(path string) (*ASNPathStore, error) {
	if path == "" {
		p, err := DefaultASNPathStorePath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	s := &ASNPathStore{
		path: path,
		data: asnPathFile{Version: asnPathStoreVer, Entries: map[string]ASNPathEntry{}},
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return s, nil
	}
	var f asnPathFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("asn path store: %w", err)
	}
	if f.Entries == nil {
		f.Entries = map[string]ASNPathEntry{}
	}
	s.data = f
	s.data.Version = asnPathStoreVer
	return s, nil
}

// Lookup returns a non-expired path for asn.
func (s *ASNPathStore) Lookup(asn string) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	asn = normalizeASNKey(asn)
	e, ok := s.data.Entries[asn]
	if !ok {
		return "", false
	}
	if time.Since(e.UpdatedAt) > ASNPathTTL {
		delete(s.data.Entries, asn)
		_ = s.saveLocked()
		return "", false
	}
	if e.Path == "" {
		return "", false
	}
	return e.Path, true
}

// Put stores the winning cascade path for asn.
func (s *ASNPathStore) Put(asn, path string) error {
	if s == nil || path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	asn = normalizeASNKey(asn)
	s.data.Entries[asn] = ASNPathEntry{
		ASN:       asn,
		Path:      path,
		UpdatedAt: time.Now().UTC(),
	}
	return s.saveLocked()
}

func (s *ASNPathStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func normalizeASNKey(asn string) string {
	if asn == "" || asn == "unknown" || asn == "UNKNOWN" {
		return "unknown"
	}
	return asn
}
