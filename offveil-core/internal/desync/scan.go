package desync

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// ScanDefaultTimeout is the total wall budget for a limited blockcheck pass.
	// Runs in the background after a protected path or endpoint fails.
	ScanDefaultTimeout = 32 * time.Second
	// ScanPerStrategyTimeout is the TLS probe budget per candidate.
	ScanPerStrategyTimeout = 6 * time.Second
	// ScanBasePort is the first SOCKS port used during scanning (main uses 18080).
	ScanBasePort = 18110
)

// StartFunc launches a ByeDPI session (overridable in tests).
type StartFunc func(Config) (Session, error)

// ScanFunc runs a limited auto-strategy pass (overridable in tests).
type ScanFunc func(ctx context.Context, cfg ScanConfig) ScanResult

// ScanConfig controls a limited auto-strategy pass.
type ScanConfig struct {
	Host string
	// Required are filtered destinations (canaries) that must all open. A
	// neutral control passing alone cannot prove that a strategy bypasses DPI.
	Required []string
	// PassThroughFirst runs each candidate the way it is deployed: an
	// untouched first group, then the candidate on reset/timeout.
	PassThroughFirst bool
	// VerifyHosts are explicit targets or independent connectivity controls.
	VerifyHosts []string
	// VerifyQuorum is the required number of successes; zero requires all hosts.
	VerifyQuorum int
	// Timeout caps the whole scan (default ScanDefaultTimeout).
	Timeout time.Duration
	// PerStrategy caps each candidate probe (default ScanPerStrategyTimeout).
	PerStrategy time.Duration
	// Concurrency bounds isolated trial helpers; defaults to two (maximum four).
	Concurrency int
	// Candidates defaults to NativeScanCandidates().
	Candidates []Strategy
	// SkipIDs are not tried (e.g. already-failed default).
	SkipIDs map[string]struct{}
	// Start launches ciadpi; nil → Start.
	Start StartFunc
	// Resolve looks up host via DoH for --no-domain strategies.
	Resolve func(ctx context.Context, host string) (netip.Addr, error)
	// AssignJob attaches trial processes to the engine Job Object.
	AssignJob     func(*os.Process) error
	BasePort      int
	BinaryPath    string
	ConnIP        string
	BindInterface string
}

// Tried records one candidate outcome during Scan.
type Tried struct {
	StrategyID string       `json:"strategy_id"`
	Class      FailClass    `json:"class"`
	Detail     string       `json:"detail,omitempty"`
	Took       string       `json:"took,omitempty"`
	Checks     []FailSignal `json:"checks,omitempty"`
	Reason     string       `json:"reason,omitempty"`
}

// ScanResult is the outcome of a limited blockcheck-style pass.
type ScanResult struct {
	OK       bool     `json:"ok"`
	Strategy Strategy `json:"strategy,omitempty"`
	Tried    []Tried  `json:"tried,omitempty"`
	Took     string   `json:"took,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

// Scan tries candidates until one ProbeTLS succeeds or the budget expires.
// No UI; intended to run inside the cascade when the current strategy fails.
func Scan(ctx context.Context, cfg ScanConfig) ScanResult {
	started := time.Now()
	out := ScanResult{}

	if cfg.Host == "" && len(cfg.Required) == 0 {
		if len(cfg.VerifyHosts) == 0 {
			return ScanResult{Reason: "missing_targets"}
		}
		cfg.Host = cfg.VerifyHosts[0]
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = ScanDefaultTimeout
	}
	if cfg.PerStrategy <= 0 {
		cfg.PerStrategy = ScanPerStrategyTimeout
	}
	if cfg.BasePort == 0 {
		cfg.BasePort = ScanBasePort
	}
	cands := cfg.Candidates
	if len(cands) == 0 {
		cands = NativeScanCandidates()
	}
	startFn := cfg.Start
	if startFn == nil {
		startFn = Start
	}

	sctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	var hosts []string
	seen := map[string]bool{}
	if cfg.Host != "" {
		hosts, seen[cfg.Host] = []string{cfg.Host}, true
	}
	for _, host := range cfg.VerifyHosts {
		if host != "" && !seen[host] {
			hosts = append(hosts, host)
			seen[host] = true
		}
	}
	if cfg.VerifyQuorum < 0 || cfg.VerifyQuorum > len(hosts) {
		return ScanResult{Reason: "invalid_quorum"}
	}
	var required []string
	for _, host := range cfg.Required {
		if host != "" && !seen[host] {
			required = append(required, host)
			seen[host] = true
		}
	}
	cfg.Required = required

	type candidate struct {
		index    int
		strategy Strategy
	}
	var candidates []candidate
	for _, strat := range cands {
		if strat.ID == "" || len(strat.Args) == 0 {
			continue
		}
		if cfg.SkipIDs != nil {
			if _, skip := cfg.SkipIDs[BaseID(strat.ID)]; skip {
				continue
			}
		}
		if cfg.PassThroughFirst {
			strat = PassThroughFirst(strat)
		}
		candidates = append(candidates, candidate{len(candidates), strat})
	}
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 2
	}
	concurrency = min(concurrency, 4, len(candidates))
	type completed struct {
		candidate
		tried Tried
		ok    bool
	}
	jobs := make(chan candidate)
	results := make(chan completed, len(candidates))
	var workers sync.WaitGroup
	for range concurrency {
		workers.Go(func() {
			for cand := range jobs {
				if sctx.Err() != nil {
					return
				}
				tried, ok := scanTrial(sctx, cfg, cand.strategy, cfg.BasePort+cand.index, hosts, startFn)
				results <- completed{cand, tried, ok}
				if ok {
					cancel()
					return
				}
			}
		})
	}
	go func() {
		defer close(jobs)
		for _, cand := range candidates {
			select {
			case <-sctx.Done():
				return
			case jobs <- cand:
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	var finished []completed
	for result := range results {
		finished = append(finished, result)
		if result.ok && !out.OK {
			out.OK, out.Strategy = true, result.strategy
		}
	}
	// Return only after every owned trial is reaped, including losing workers.
	sort.Slice(finished, func(i, j int) bool { return finished[i].index < finished[j].index })
	for _, result := range finished {
		out.Tried = append(out.Tried, result.tried)
	}
	out.Took = time.Since(started).Round(time.Millisecond).String()
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		out.OK, out.Strategy, out.Reason = false, Strategy{}, "timeout"
	case ctx.Err() != nil:
		out.OK, out.Strategy, out.Reason = false, Strategy{}, "canceled"
	case out.OK:
		out.Reason = "ok"
	case len(candidates) == 0:
		out.Reason = "no_candidates"
	case sctx.Err() != nil:
		out.Reason = "timeout"
	default:
		out.Reason = "exhausted"
	}
	return out
}

func scanTrial(ctx context.Context, cfg ScanConfig, strat Strategy, port int, hosts []string, startFn StartFunc) (Tried, bool) {
	t0 := time.Now()
	trialCtx, trialCancel := context.WithTimeout(ctx, cfg.PerStrategy)
	defer trialCancel()
	trialCfg := Config{
		Context:       trialCtx,
		BinaryPath:    cfg.BinaryPath,
		ListenIP:      "127.0.0.1",
		ListenPort:    port,
		Strategy:      strat,
		AssignJob:     cfg.AssignJob,
		Resolve:       cfg.Resolve,
		ProbeHost:     "", // probe explicitly below
		ProbeTimeout:  cfg.PerStrategy,
		ConnIP:        cfg.ConnIP,
		BindInterface: cfg.BindInterface,
	}
	sess, err := startFn(trialCfg)
	if sess != nil {
		defer sess.Close()
	}
	if err != nil {
		reason := "startup_failed"
		if trialCtx.Err() == context.Canceled {
			reason = "canceled"
		}
		return Tried{
			StrategyID: strat.ID,
			Class:      FailTimeout,
			Detail:     "start: " + err.Error(),
			Took:       time.Since(t0).Round(time.Millisecond).String(),
			Reason:     reason,
		}, false
	}
	if sess == nil {
		return Tried{StrategyID: strat.ID, Class: FailTimeout, Detail: "start: no session"}, false
	}
	// A slow target cannot spend the other targets' verification budget.
	// At most four probes run per helper, each using the same trial deadline.
	all := append(append([]string(nil), cfg.Required...), hosts...)
	checks := make([]FailSignal, len(all))
	var probes sync.WaitGroup
	var timelySuccess, requiredSuccess atomic.Int32
	slots := make(chan struct{}, 4)
	for i, host := range all {
		probes.Go(func() {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-trialCtx.Done():
				checks[i] = FailSignal{Target: host, Class: FailTimeout}
				return
			}
			checks[i] = sess.ProbeTLS(host)
			if checks[i].Class == FailOK && trialCtx.Err() == nil {
				if i < len(cfg.Required) {
					requiredSuccess.Add(1)
				} else {
					timelySuccess.Add(1)
				}
			}
		})
	}
	probes.Wait()
	class := FailOK
	detail := ""
	passed := 0
	for i, sig := range checks {
		if sig.Class == FailOK && i >= len(cfg.Required) {
			passed++
		}
		if sig.Class != FailOK && class == FailOK {
			class, detail = sig.Class, sig.Detail
		}
	}
	quorum := cfg.VerifyQuorum
	if quorum <= 0 {
		quorum = len(hosts)
	}
	requiredOK := int(requiredSuccess.Load()) == len(cfg.Required)
	if passed >= quorum && requiredOK {
		class, detail = FailOK, ""
	}
	// A cancelled/expired trial cannot win even if an injected probe
	// ignores its context and returns success late.
	if trialCtx.Err() != nil {
		class = FailTimeout
	}
	quorumPassed := cfg.VerifyQuorum > 0 && int(timelySuccess.Load()) >= cfg.VerifyQuorum && requiredOK && ctx.Err() == nil
	if quorumPassed {
		class, detail = FailOK, ""
	}
	if !requiredOK && class == FailOK {
		class = FailTimeout
	}
	took := time.Since(t0).Round(time.Millisecond).String()
	tried := Tried{
		StrategyID: strat.ID,
		Class:      class,
		Detail:     detail,
		Took:       took,
		Checks:     checks,
	}
	if trialCtx.Err() == context.Canceled && !quorumPassed {
		tried.Reason = "canceled"
	}
	if trialCtx.Err() == context.DeadlineExceeded && !quorumPassed {
		tried.Reason = "timeout"
	}
	slog.Info("desync scan: candidate",
		"strategy", strat.ID,
		"class", class,
		"took", took,
	)
	return tried, class == FailOK
}

// ScanEnvTimeout allows OFFVEIL_DESYNC_SCAN_TIMEOUT (e.g. "25s") for diagnostics.
func ScanEnvTimeout() time.Duration {
	v := os.Getenv("OFFVEIL_DESYNC_SCAN_TIMEOUT")
	if v == "" {
		return ScanDefaultTimeout
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return ScanDefaultTimeout
	}
	return d
}

// FormatScanSummary is a short log line (no PII).
func FormatScanSummary(r ScanResult) string {
	if r.OK {
		return fmt.Sprintf("ok strategy=%s tried=%d took=%s", r.Strategy.ID, len(r.Tried), r.Took)
	}
	return fmt.Sprintf("fail reason=%s tried=%d took=%s", r.Reason, len(r.Tried), r.Took)
}
