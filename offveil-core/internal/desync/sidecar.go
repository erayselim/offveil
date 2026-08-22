package desync

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type session struct {
	mu sync.Mutex

	cfg      Config
	cmd      *exec.Cmd
	socks    string
	strategy Strategy

	up           atomic.Bool
	failTimeouts atomic.Int64
	failSSL      atomic.Int64
	failReset    atomic.Int64
	lastProbe    atomic.Value // FailClass
	lastProbeAt  atomic.Value // string RFC3339
}

// Start launches ciadpi as a local SOCKS desync outbound.
func Start(cfg Config) (Session, error) {
	if cfg.ListenIP == "" {
		cfg.ListenIP = "127.0.0.1"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 18080
	}
	if cfg.Strategy.ID == "" || len(cfg.Strategy.Args) == 0 {
		cfg.Strategy = DefaultSafeStrategy()
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 8 * time.Second
	}

	bin, err := resolveBinary(cfg.BinaryPath)
	if err != nil {
		return nil, err
	}
	cfg.BinaryPath = bin

	args := BuildArgs(cfg.ListenIP, cfg.ListenPort, cfg.Strategy)
	cmd := exec.Command(bin, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("desync: start ciadpi: %w", err)
	}
	if cfg.AssignJob != nil && cmd.Process != nil {
		if err := cfg.AssignJob(cmd.Process); err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return nil, fmt.Errorf("desync: assign job: %w", err)
		}
	}

	s := &session{
		cfg:      cfg,
		cmd:      cmd,
		socks:    net.JoinHostPort(cfg.ListenIP, strconv.Itoa(cfg.ListenPort)),
		strategy: cfg.Strategy,
	}
	s.lastProbe.Store(FailClass(""))
	s.lastProbeAt.Store("")

	if err := waitSOCKS(s.socks, 5*time.Second); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("desync: socks not ready: %w", err)
	}
	s.up.Store(true)
	slog.Info("desync: byeDPI up",
		"socks", s.socks,
		"strategy", s.strategy.ID,
		"pid", cmd.Process.Pid,
		"bin", bin,
	)

	if cfg.ProbeHost != "" {
		sig := s.ProbeTLS(cfg.ProbeHost)
		if cfg.Sink != nil {
			if sig.Class == FailOK {
				cfg.Sink.OnDesyncOK(cfg.ProbeHost, s.strategy.ID)
			} else {
				cfg.Sink.OnDesyncFail(sig)
			}
		}
	}

	return s, nil
}

func (s *session) Info() Info {
	info := Info{
		SocksAddr:    s.socks,
		StrategyID:   s.strategy.ID,
		BinaryPath:   s.cfg.BinaryPath,
		Up:           s.up.Load(),
		FailTimeouts: int(s.failTimeouts.Load()),
		FailSSLErrs:  int(s.failSSL.Load()),
		FailResets:   int(s.failReset.Load()),
	}
	if s.cmd != nil && s.cmd.Process != nil {
		info.PID = s.cmd.Process.Pid
	}
	if v, ok := s.lastProbe.Load().(FailClass); ok {
		info.LastProbe = v
	}
	if v, ok := s.lastProbeAt.Load().(string); ok {
		info.LastProbeAt = v
	}
	return info
}

func (s *session) SocksAddr() string  { return s.socks }
func (s *session) StrategyID() string { return s.strategy.ID }

func (s *session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.up.Store(false)
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	_ = s.cmd.Process.Kill()
	_, _ = s.cmd.Process.Wait()
	s.cmd = nil
	slog.Info("desync: byeDPI stopped", "socks", s.socks)
	return nil
}

func (s *session) recordProbe(sig FailSignal) {
	s.lastProbe.Store(sig.Class)
	s.lastProbeAt.Store(sig.At.UTC().Format(time.RFC3339))
	switch sig.Class {
	case FailTimeout:
		s.failTimeouts.Add(1)
	case FailSSLErr:
		s.failSSL.Add(1)
	case FailReset:
		s.failReset.Add(1)
	}
}

func waitSOCKS(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	if last == nil {
		last = fmt.Errorf("timeout")
	}
	return last
}

func resolveBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("desync binary %q: %w", explicit, err)
		}
		return explicit, nil
	}
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "ciadpi.exe"),
			filepath.Join(dir, "ciadpi"),
			filepath.Join(dir, "third_party", "byedpi", "ciadpi.exe"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "ciadpi.exe"),
			filepath.Join(wd, "third_party", "byedpi", "ciadpi.exe"),
			filepath.Join(wd, "..", "third_party", "byedpi", "ciadpi.exe"),
		)
	}
	// Repo-relative when running tests from package dir.
	candidates = append(candidates,
		filepath.Join("third_party", "byedpi", "ciadpi.exe"),
	)
	if runtime.GOOS != "windows" {
		candidates = append(candidates, "ciadpi")
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			abs, err := filepath.Abs(c)
			if err != nil {
				return c, nil
			}
			return abs, nil
		}
	}
	return "", fmt.Errorf("ciadpi not found (run scripts/fetch-byedpi.ps1 and place next to offveil-core.exe)")
}
