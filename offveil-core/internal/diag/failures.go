package diag

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/proc"
	"github.com/erayselim/offveil/offveil-core/internal/version"
)

const maxFailures = 64

var failuresMu sync.Mutex

type Failure struct {
	At                string         `json:"at"`
	Component         string         `json:"component"`
	Event             string         `json:"event"`
	Attempt           int            `json:"attempt,omitempty"`
	Target            string         `json:"target,omitempty"`
	Provider          string         `json:"provider,omitempty"`
	Strategy          string         `json:"strategy,omitempty"`
	Reason            string         `json:"reason,omitempty"`
	Stage             string         `json:"stage,omitempty"`
	Class             string         `json:"class,omitempty"`
	ExitOrigin        string         `json:"exit_origin,omitempty"`
	FromMode          string         `json:"from_mode,omitempty"`
	ToMode            string         `json:"to_mode,omitempty"`
	FingerprintBefore string         `json:"fingerprint_before,omitempty"`
	FingerprintAfter  string         `json:"fingerprint_after,omitempty"`
	Version           string         `json:"version,omitempty"`
	Generation        uint64         `json:"generation,omitempty"`
	Exit              *proc.ExitInfo `json:"exit,omitempty"`
}

func ReadFailures() []Failure {
	failuresMu.Lock()
	defer failuresMu.Unlock()
	return readFailures()
}

func readFailures() []Failure {
	dir, err := Dir()
	if err != nil {
		return nil
	}
	f, err := os.Open(filepath.Join(dir, "failures.json"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var history []Failure
	if json.NewDecoder(io.LimitReader(f, 64<<10)).Decode(&history) != nil {
		return nil
	}
	if len(history) > maxFailures {
		history = history[len(history)-maxFailures:]
	}
	return history
}

// RecordFailure retains only process facts, never raw sidecar output or hosts.
func RecordFailure(failure Failure) error {
	failuresMu.Lock()
	defer failuresMu.Unlock()
	if failure.Version == "" {
		failure.Version = version.Version
	}
	if failure.At == "" {
		failure.At = time.Now().UTC().Format(time.RFC3339)
	}
	history := append(readFailures(), failure)
	if len(history) > maxFailures {
		history = history[len(history)-maxFailures:]
	}
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := ensureReadableDir(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".failures-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := json.NewEncoder(f).Encode(history); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		err = os.Rename(f.Name(), filepath.Join(dir, "failures.json"))
		if err == nil || runtime.GOOS != "windows" || attempt == 4 {
			return err
		}
		// Windows readers can briefly hold a file without delete sharing.
		time.Sleep(20 * time.Millisecond)
	}
}
