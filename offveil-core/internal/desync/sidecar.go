package desync

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/proc"
	"github.com/erayselim/offveil/offveil-core/internal/sidecar"
)

type session struct {
	mu sync.Mutex

	cfg      Config
	child    *proc.Child
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
		cfg.Strategy = NativeSafeStrategy()
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 8 * time.Second
	}

	bin, err := resolveBinary(cfg.BinaryPath)
	if err != nil {
		return nil, err
	}
	cfg.BinaryPath = bin

	args := BuildArgsBind(cfg.ListenIP, cfg.ListenPort, cfg.Strategy, cfg.ConnIP)
	stderr := &proc.TailBuffer{}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = nil
	cmd.Stderr = stderr
	if runtime.GOOS == "darwin" && cfg.BindInterface != "" {
		cmd.Env = append(os.Environ(), "OFFVEIL_BIND_INTERFACE="+cfg.BindInterface)
	}
	proc.PrepareCmd(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("desync: start ciadpi: %w", err)
	}
	if cfg.AssignJob != nil && cmd.Process != nil {
		if err := cfg.AssignJob(cmd.Process); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, fmt.Errorf("desync: assign job: %w", err)
		}
	}

	s := &session{
		cfg:      cfg,
		child:    proc.WatchChild(cmd),
		socks:    net.JoinHostPort(cfg.ListenIP, strconv.Itoa(cfg.ListenPort)),
		strategy: cfg.Strategy,
	}
	s.lastProbe.Store(FailClass(""))
	s.lastProbeAt.Store("")

	if err := proc.WaitTCP(s.socks, 5*time.Second, s.child); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("desync: socks not ready: %w; stderr: %s", err, stderr.String())
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
		SocksAddr:     s.socks,
		StrategyID:    s.strategy.ID,
		BindInterface: s.cfg.BindInterface,
		BinaryPath:    s.cfg.BinaryPath,
		Up:            s.up.Load() && s.child.Running(),
		FailTimeouts:  int(s.failTimeouts.Load()),
		FailSSLErrs:   int(s.failSSL.Load()),
		FailResets:    int(s.failReset.Load()),
	}
	info.PID = s.child.PID()
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
	s.child.Close()
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
	return proc.WaitTCP(addr, timeout, nil)
}

func resolveBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("desync binary %q: %w", explicit, err)
		}
		return explicit, nil
	}
	return sidecar.Locate(sidecar.ByeDPI)
}
