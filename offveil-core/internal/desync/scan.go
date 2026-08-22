package desync

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"
)

const (
	// ScanDefaultTimeout is the total wall budget for a limited blockcheck pass.
	// Zapret/SplitWire blockcheck is minutes; offveil must stay UI-snappy.
	// Research: fail-fast → tunnel escalate beats a long invisible scan (2026).
	ScanDefaultTimeout = 12 * time.Second
	// ScanPerStrategyTimeout is the TLS probe budget per candidate.
	ScanPerStrategyTimeout = 4 * time.Second
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
	// Timeout caps the whole scan (default ScanDefaultTimeout).
	Timeout time.Duration
	// PerStrategy caps each candidate probe (default ScanPerStrategyTimeout).
	PerStrategy time.Duration
	// Candidates defaults to ScanCandidates().
	Candidates []Strategy
	// SkipIDs are not tried (e.g. already-failed default).
	SkipIDs map[string]struct{}
	// Start launches ciadpi; nil → Start.
	Start StartFunc
	// Resolve looks up host via DoH for --no-domain strategies.
	Resolve func(ctx context.Context, host string) (netip.Addr, error)
	// AssignJob attaches trial processes to the engine Job Object.
	AssignJob func(*os.Process) error
	BasePort  int
	BinaryPath string
}

// Tried records one candidate outcome during Scan.
type Tried struct {
	StrategyID string    `json:"strategy_id"`
	Class      FailClass `json:"class"`
	Detail     string    `json:"detail,omitempty"`
	Took       string    `json:"took,omitempty"`
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

	if cfg.Host == "" {
		cfg.Host = "discord.com"
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
		cands = ScanCandidates()
	}
	startFn := cfg.Start
	if startFn == nil {
		startFn = Start
	}

	deadline := time.Now().Add(cfg.Timeout)
	sctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	port := cfg.BasePort
	for _, strat := range cands {
		if strat.ID == "" || len(strat.Args) == 0 {
			continue
		}
		if cfg.SkipIDs != nil {
			if _, skip := cfg.SkipIDs[strat.ID]; skip {
				continue
			}
		}
		select {
		case <-sctx.Done():
			out.Reason = "timeout"
			out.Took = time.Since(started).Round(time.Millisecond).String()
			return out
		default:
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			out.Reason = "timeout"
			out.Took = time.Since(started).Round(time.Millisecond).String()
			return out
		}
		per := cfg.PerStrategy
		if per > remain {
			per = remain
		}

		trialPort := port
		port++
		t0 := time.Now()
		trialCfg := Config{
			BinaryPath:   cfg.BinaryPath,
			ListenIP:     "127.0.0.1",
			ListenPort:   trialPort,
			Strategy:     strat,
			AssignJob:    cfg.AssignJob,
			Resolve:      cfg.Resolve,
			ProbeHost:    "", // probe explicitly below
			ProbeTimeout: per,
		}
		sess, err := startFn(trialCfg)
		if err != nil {
			out.Tried = append(out.Tried, Tried{
				StrategyID: strat.ID,
				Class:      FailTimeout,
				Detail:     "start: " + err.Error(),
				Took:       time.Since(t0).Round(time.Millisecond).String(),
			})
			slog.Debug("desync scan: start failed", "strategy", strat.ID, "err", err)
			continue
		}

		sig := sess.ProbeTLS(cfg.Host)
		_ = sess.Close()
		took := time.Since(t0).Round(time.Millisecond).String()
		out.Tried = append(out.Tried, Tried{
			StrategyID: strat.ID,
			Class:      sig.Class,
			Detail:     sig.Detail,
			Took:       took,
		})
		slog.Info("desync scan: candidate",
			"strategy", strat.ID,
			"class", sig.Class,
			"took", took,
		)
		if sig.Class == FailOK {
			out.OK = true
			out.Strategy = strat
			out.Took = time.Since(started).Round(time.Millisecond).String()
			out.Reason = "ok"
			return out
		}
	}

	out.Reason = "exhausted"
	if len(out.Tried) == 0 {
		out.Reason = "no_candidates"
	}
	out.Took = time.Since(started).Round(time.Millisecond).String()
	return out
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
