package repair

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/policy"
)

// Step is one best-effort repair action.
type Step struct {
	Name   string
	OK     bool
	Detail string
}

// Result is the outcome of Run.
type Result struct {
	Steps []Step
}

func (r *Result) add(name string, err error, detail string) {
	s := Step{Name: name, OK: err == nil, Detail: detail}
	if err != nil {
		if s.Detail == "" {
			s.Detail = err.Error()
		}
		slog.Warn("repair: step failed", "name", name, "err", err)
	} else {
		slog.Info("repair: step ok", "name", name, "detail", detail)
	}
	r.Steps = append(r.Steps, s)
}

// Run restores leftover DNS/NRPT/adapter state and clears learned DPI policy.
func Run() Result {
	var r Result
	network(&r)
	r.add("policy", ClearLearnedState(), "")
	return r
}

// LeftoverNetwork restores NRPT / adapter DNS leftovers without clearing
// learned DPI policy. Used on service uninstall so upgrades do not wipe caches.
func LeftoverNetwork() Result {
	var r Result
	network(&r)
	return r
}

// ClearLearnedState deletes persisted desync strategy + ASN path caches.
func ClearLearnedState() error {
	var first error
	remove := func(path string, err error) {
		if err != nil {
			if first == nil {
				first = err
			}
			return
		}
		if path == "" {
			return
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
		// Drop empty dir when we created a file-only cache.
		_ = os.Remove(filepath.Dir(path))
	}
	p, err := desync.DefaultStrategyStorePath()
	remove(p, err)
	p, err = policy.DefaultASNPathStorePath()
	remove(p, err)
	return first
}
