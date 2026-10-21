package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
)

type stagedError struct {
	stage, target string
	err           error
}

func (e *stagedError) Error() string                   { return e.stage + ": " + e.err.Error() }
func (e *stagedError) Unwrap() error                   { return e.err }
func stageError(stage, target string, err error) error { return &stagedError{stage, target, err} }

func providerFailure(s *session, provider ProviderID, class FailClass, err error) ProviderFailure {
	f := ProviderFailure{ProviderID: provider, Class: class, Reason: providerFailureReason(err)}
	var stage *stagedError
	if errors.As(err, &stage) {
		f.Stage, f.Target = stage.stage, stage.target
	}
	if s != nil {
		f.Controls = append([]ControlResult(nil), s.controls...)
		f.Exit = s.child.Exit()
		if f.Exit != nil {
			f.ExitOrigin = s.exitOrigin
			if f.ExitOrigin == "" {
				f.ExitOrigin = "natural"
			}
		}
	}
	return f
}

func normalizeControls(cfg *Config) error {
	if len(cfg.ControlHosts) == 0 {
		cfg.ControlHosts = ruleset.DefaultControlHosts()
	}
	var hosts []string
	seen := map[string]bool{}
	for _, host := range cfg.ControlHosts {
		host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
		if host == "" || net.ParseIP(host) != nil || strings.ContainsAny(host, "/:\\ @") || !strings.Contains(host, ".") {
			return fmt.Errorf("invalid TLS control hostname")
		}
		if !seen[host] {
			hosts = append(hosts, host)
			seen[host] = true
		}
	}
	if cfg.ControlQuorum == 0 {
		cfg.ControlQuorum = 2
	}
	if cfg.ControlQuorum < 2 || cfg.ControlQuorum > len(hosts) {
		return fmt.Errorf("control quorum requires at least two independent hosts")
	}
	if len(hosts) > 16 {
		return fmt.Errorf("too many TLS control hosts")
	}
	cfg.ControlHosts = hosts
	return nil
}

func checkControls(ctx context.Context, hosts []string, quorum int, probe func(context.Context, string) FailSignal) ([]ControlResult, bool) {
	results := make([]ControlResult, len(hosts))
	var work sync.WaitGroup
	for i, host := range hosts {
		work.Add(1)
		go func(i int, host string) {
			defer work.Done()
			sig := probe(ctx, host)
			at := sig.At
			if at.IsZero() {
				at = time.Now().UTC()
			}
			results[i] = ControlResult{Target: host, Class: sig.Class, At: at.UTC().Format(time.RFC3339)}
		}(i, host)
	}
	work.Wait()
	passed := 0
	for _, result := range results {
		if result.Class == FailOK {
			passed++
		}
	}
	return results, quorum >= 2 && passed >= quorum
}
