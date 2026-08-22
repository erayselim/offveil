package desync

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
	// StrategyStoreTTL is how long an ISS-keyed strategy remains trusted.
	StrategyStoreTTL = 7 * 24 * time.Hour
	strategyStoreVer = 1
)

// PersistedStrategy is one ASN → ByeDPI strategy binding.
type PersistedStrategy struct {
	ASN        string    `json:"asn"`
	StrategyID string    `json:"strategy_id"`
	Args       []string  `json:"args"`
	Host       string    `json:"host,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
	TTLSeconds int64     `json:"ttl_seconds"`
}

type strategyStoreFile struct {
	Version int                          `json:"version"`
	Entries map[string]PersistedStrategy `json:"entries"`
}

// StrategyStore persists winning desync strategies keyed by ISS ASN.
type StrategyStore struct {
	mu   sync.Mutex
	path string
	data strategyStoreFile
}

// StrategyCacheDir returns ProgramData/offveil/desync (Windows) or XDG path.
func StrategyCacheDir() (string, error) {
	if d := os.Getenv("OFFVEIL_DESYNC_CACHE"); d != "" {
		return d, nil
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "offveil", "desync"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "offveil", "desync"), nil
}

// DefaultStrategyStorePath is desync-strategies.json under StrategyCacheDir.
func DefaultStrategyStorePath() (string, error) {
	dir, err := StrategyCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "desync-strategies.json"), nil
}

// OpenStrategyStore loads or creates a store at path (empty → default path).
func OpenStrategyStore(path string) (*StrategyStore, error) {
	if path == "" {
		p, err := DefaultStrategyStorePath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	s := &StrategyStore{
		path: path,
		data: strategyStoreFile{
			Version: strategyStoreVer,
			Entries: make(map[string]PersistedStrategy),
		},
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
	var f strategyStoreFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("desync strategy store: %w", err)
	}
	if f.Entries == nil {
		f.Entries = make(map[string]PersistedStrategy)
	}
	if f.Version == 0 {
		f.Version = strategyStoreVer
	}
	s.data = f
	return s, nil
}

// Path returns the on-disk file path.
func (s *StrategyStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Lookup returns a non-expired strategy for asn.
func (s *StrategyStore) Lookup(asn string) (Strategy, bool) {
	if s == nil {
		return Strategy{}, false
	}
	asn = normalizeASN(asn)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data.Entries[asn]
	if !ok {
		return Strategy{}, false
	}
	ttl := time.Duration(e.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = StrategyStoreTTL
	}
	if time.Since(e.UpdatedAt) > ttl {
		delete(s.data.Entries, asn)
		_ = s.saveLocked()
		return Strategy{}, false
	}
	if e.StrategyID == "" || len(e.Args) == 0 {
		return Strategy{}, false
	}
	return Strategy{ID: e.StrategyID, Args: append([]string(nil), e.Args...), Note: "asn-cache"}, true
}

// Put stores a winning strategy for asn.
func (s *StrategyStore) Put(asn string, strat Strategy, host string) error {
	if s == nil {
		return nil
	}
	if strat.ID == "" || len(strat.Args) == 0 {
		return fmt.Errorf("desync strategy store: empty strategy")
	}
	asn = normalizeASN(asn)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Entries == nil {
		s.data.Entries = make(map[string]PersistedStrategy)
	}
	s.data.Entries[asn] = PersistedStrategy{
		ASN:        asn,
		StrategyID: strat.ID,
		Args:       append([]string(nil), strat.Args...),
		Host:       host,
		UpdatedAt:  time.Now().UTC(),
		TTLSeconds: int64(StrategyStoreTTL / time.Second),
	}
	return s.saveLocked()
}

// Delete removes the ASN entry (failed cached strategy).
func (s *StrategyStore) Delete(asn string) error {
	if s == nil {
		return nil
	}
	asn = normalizeASN(asn)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Entries[asn]; !ok {
		return nil
	}
	delete(s.data.Entries, asn)
	return s.saveLocked()
}

func (s *StrategyStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}
	s.data.Version = strategyStoreVer
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func normalizeASN(asn string) string {
	if asn == "" {
		return "unknown"
	}
	return asn
}
