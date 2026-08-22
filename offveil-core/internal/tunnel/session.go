package tunnel

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type session struct {
	mu sync.Mutex

	cfg        Config
	cmd        *exec.Cmd
	socks      string
	provider   ProviderID
	configPath string
	binPath    string

	up             atomic.Bool
	retryHint      atomic.Bool
	failDetail     atomic.Value // string
	lastProbe      atomic.Value // FailClass
	lastProbeAt    atomic.Value // string
	failoverFrom   ProviderID
	providersTried []ProviderID
}

// Start brings up selective tunnel with WARP↔Reality failover.
// Soft-fails (returns session, nil) only after all providers are exhausted.
func Start(cfg Config) (Session, error) {
	if cfg.ListenIP == "" {
		cfg.ListenIP = "127.0.0.1"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 18081
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 12 * time.Second
	}
	if len(cfg.TunnelDomains) == 0 {
		cfg.TunnelDomains = DefaultTunnelDomains()
	}
	if len(cfg.DirectDomains) == 0 {
		cfg.DirectDomains = DefaultDirectDomains()
	}

	dataDir, err := resolveDataDir(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	cfg.DataDir = dataDir

	if strings.EqualFold(strings.TrimSpace(cfg.AllowlistOutbound), "desync") {
		return startDesyncDataplane(cfg)
	}

	order := ProviderOrder(cfg, dataDir)
	if len(order) == 0 {
		return failSession(cfg, ProviderWARP, FailAuth, fmt.Errorf("no tunnel provider"), nil, "")
	}

	var (
		tried      []ProviderID
		lastFail   Session
		prevFailed ProviderID
	)
	for i, attempt := range order {
		tried = append(tried, attempt.ID)
		s, ok, failClass, failErr := startOne(cfg, attempt)
		if ok {
			if prevFailed != "" {
				s.failoverFrom = prevFailed
				slog.Info("tunnel: failover ok",
					"from", prevFailed,
					"to", attempt.ID,
					"tried", tried,
				)
			}
			s.providersTried = append([]ProviderID(nil), tried...)
			if cfg.Sink != nil && cfg.ProbeHost != "" {
				info := s.Info()
				if info.LastProbe == FailOK || info.LastProbe == "" {
					cfg.Sink.OnTunnelOK(cfg.ProbeHost, string(attempt.ID))
				}
			}
			return s, nil
		}
		prevFailed = attempt.ID
		slog.Warn("tunnel: provider failed, trying next",
			"provider", attempt.ID,
			"class", failClass,
			"err", failErr,
			"remaining", len(order)-i-1,
		)
		if s != nil {
			_ = s.Close()
			lastFail = softFailSession(cfg, attempt.ID, failClass, failErr, tried, prevFailed)
		} else {
			lastFail = softFailSession(cfg, attempt.ID, failClass, failErr, tried, prevFailed)
		}
	}

	// All providers failed → surface retry_hint once.
	detail := "all providers failed"
	class := FailAuth
	if lf, ok := lastFail.(*session); ok {
		if v, ok := lf.failDetail.Load().(string); ok && v != "" {
			detail = v
		}
		if v, ok := lf.lastProbe.Load().(FailClass); ok && v != "" {
			class = v
		}
	}
	return failSession(cfg, order[len(order)-1].ID, class, fmt.Errorf("%s", detail), tried, prevFailed)
}

// startOne launches one provider. ok=false means try next (or final fail).
// Does not call Sink - Start owns policy notifications.
func startOne(cfg Config, attempt providerAttempt) (s *session, ok bool, class FailClass, err error) {
	provider := attempt.ID
	reality := attempt.Reality

	var warp *WARPProfile
	if provider == ProviderWARP {
		_, warp, err = LoadOrRegisterWARP(cfg.DataDir, nil)
		if err != nil {
			return nil, false, FailAuth, fmt.Errorf("warp: %w", err)
		}
	}

	build, err := BuildSingBox(buildParamsFrom(cfg, provider, warp, reality))
	if err != nil {
		return nil, false, FailAuth, err
	}

	cfgPath := filepath.Join(cfg.DataDir, "sing-box-tunnel.json")
	if err := os.WriteFile(cfgPath, build.JSON, 0o600); err != nil {
		return nil, false, FailAuth, err
	}

	s = &session{
		cfg:        cfg,
		socks:      net.JoinHostPort(cfg.ListenIP, strconv.Itoa(cfg.ListenPort)),
		provider:   provider,
		configPath: cfgPath,
	}
	s.lastProbe.Store(FailClass(""))
	s.lastProbeAt.Store("")
	s.failDetail.Store("")

	if cfg.SkipStart {
		s.up.Store(true)
		s.lastProbe.Store(FailOK)
		return s, true, FailOK, nil
	}

	bin, err := resolveBinary(cfg.BinaryPath)
	if err != nil {
		return nil, false, FailDial, fmt.Errorf("sing-box: %w", err)
	}
	s.binPath = bin

	if err := ensureWintunBeside(bin); err != nil {
		slog.Warn("tunnel: wintun.dll not staged beside sing-box", "err", err)
	}

	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, false, FailDial, fmt.Errorf("sing-box start: %w", err)
	}
	if cfg.AssignJob != nil && cmd.Process != nil {
		if err := cfg.AssignJob(cmd.Process); err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return nil, false, FailDial, fmt.Errorf("assign job: %w", err)
		}
	}
	s.cmd = cmd

	if err := waitSOCKS(s.socks, 8*time.Second); err != nil {
		_ = s.Close()
		return nil, false, FailDial, fmt.Errorf("socks not ready: %w", err)
	}
	s.up.Store(true)
	slog.Info("tunnel: selective outbound up",
		"provider", provider,
		"socks", s.socks,
		"pid", cmd.Process.Pid,
		"selective", true,
	)

	if cfg.ProbeHost != "" {
		if IsDirectHost(cfg.ProbeHost, cfg.DirectDomains) {
			slog.Warn("tunnel: probe host is on DIRECT list; skipping", "host", cfg.ProbeHost)
			s.lastProbe.Store(FailOK)
			return s, true, FailOK, nil
		}
		sig := s.ProbeTLS(cfg.ProbeHost)
		if sig.Class != FailOK {
			detail := sig.Detail
			_ = s.Close()
			return nil, false, sig.Class, fmt.Errorf("probe: %s", detail)
		}
		s.lastProbe.Store(FailOK)
	} else {
		s.lastProbe.Store(FailOK)
	}
	return s, true, FailOK, nil
}

func softFailSession(cfg Config, provider ProviderID, class FailClass, err error, tried []ProviderID, from ProviderID) *session {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	s := &session{
		cfg:            cfg,
		socks:          net.JoinHostPort(cfg.ListenIP, strconv.Itoa(cfg.ListenPort)),
		provider:       provider,
		providersTried: append([]ProviderID(nil), tried...),
		failoverFrom:   from,
	}
	s.lastProbe.Store(class)
	s.lastProbeAt.Store(time.Now().UTC().Format(time.RFC3339))
	s.retryHint.Store(false) // intermediate - not yet final
	s.failDetail.Store(detail)
	s.up.Store(false)
	return s
}

// failSession returns an up=false session that exposes retry_hint for UI (final).
func failSession(cfg Config, provider ProviderID, class FailClass, err error, tried []ProviderID, from ProviderID) (Session, error) {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	s := &session{
		cfg:            cfg,
		socks:          net.JoinHostPort(cfg.ListenIP, strconv.Itoa(cfg.ListenPort)),
		provider:       provider,
		providersTried: append([]ProviderID(nil), tried...),
		failoverFrom:   from,
	}
	s.lastProbe.Store(class)
	s.lastProbeAt.Store(time.Now().UTC().Format(time.RFC3339))
	s.retryHint.Store(true)
	s.failDetail.Store(detail)
	s.up.Store(false)
	if cfg.Sink != nil && cfg.ProbeHost != "" {
		cfg.Sink.OnTunnelFail(FailSignal{
			Target:     cfg.ProbeHost,
			Class:      class,
			ProviderID: string(provider),
			Detail:     detail,
			At:         time.Now().UTC(),
		})
	}
	slog.Warn("tunnel: failed", "provider", provider, "class", class, "err", detail, "tried", tried)
	return s, nil
}

func (s *session) Info() Info {
	info := Info{
		SocksAddr:      s.socks,
		ProviderID:     s.provider,
		BinaryPath:     s.binPath,
		ConfigPath:     s.configPath,
		Up:             s.up.Load(),
		Selective:      true,
		RetryHint:      s.retryHint.Load(),
		TunnelHosts:    s.cfg.TunnelDomains,
		DirectHosts:    s.cfg.DirectDomains,
		FailoverFrom:   s.failoverFrom,
		ProvidersTried: append([]ProviderID(nil), s.providersTried...),
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
	if v, ok := s.failDetail.Load().(string); ok {
		info.FailDetail = v
	}
	return info
}

func (s *session) SocksAddr() string      { return s.socks }
func (s *session) ProviderID() ProviderID { return s.provider }

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
	slog.Info("tunnel: stopped", "socks", s.socks)
	return nil
}

func (s *session) recordProbe(sig FailSignal) {
	s.lastProbe.Store(sig.Class)
	s.lastProbeAt.Store(sig.At.UTC().Format(time.RFC3339))
	if sig.Class != FailOK {
		s.retryHint.Store(true)
		s.failDetail.Store(sig.Detail)
	}
}

func startDesyncDataplane(cfg Config) (Session, error) {
	// ByeDPI already probed TLS; don't add another SOCKS wait on the hot path.
	cfg.ProbeHost = ""
	s, ok, class, err := startOne(cfg, providerAttempt{ID: ProviderDesync})
	if ok {
		s.providersTried = []ProviderID{ProviderDesync}
		slog.Info("tunnel: desync dataplane up", "socks", s.socks, "tun", cfg.EnableTUN)
		return s, nil
	}
	detail := "desync dataplane failed"
	if err != nil {
		detail = err.Error()
	}
	return failSession(cfg, ProviderDesync, class, fmt.Errorf("%s", detail), []ProviderID{ProviderDesync}, "")
}

func buildParamsFrom(cfg Config, provider ProviderID, warp *WARPProfile, reality *RealityCredentials) BuildParams {
	host, port := splitDesyncSOCKS(cfg.DesyncSOCKS)
	iface := cfg.TUNInterface
	if iface == "" {
		iface = "offveil"
	}
	addr := cfg.TUNAddress
	if addr == "" {
		addr = defaultTUNAddress
	}
	return BuildParams{
		Provider:          provider,
		WARP:              warp,
		Reality:           reality,
		ListenIP:          cfg.ListenIP,
		ListenPort:        cfg.ListenPort,
		TunnelDomains:     cfg.TunnelDomains,
		DirectDomains:     cfg.DirectDomains,
		EnableTUN:         cfg.EnableTUN,
		TUNInterface:      iface,
		TUNAddress:        addr,
		TUNMTU:            cfg.TUNMTU,
		RouteCIDRs:        append([]string{}, cfg.RouteCIDRs...),
		ExcludeCIDRs:      append([]string{}, cfg.ExcludeCIDRs...),
		AllowlistOutbound: cfg.AllowlistOutbound,
		DesyncSOCKSHost:   host,
		DesyncSOCKSPort:   port,
	}
}

func splitDesyncSOCKS(addr string) (string, int) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "127.0.0.1", 18080
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1", 18080
	}
	n, _ := strconv.Atoi(port)
	if n == 0 {
		n = 18080
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return host, n
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

func resolveDataDir(explicit string) (string, error) {
	if explicit != "" {
		return explicit, os.MkdirAll(explicit, 0o700)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Join(filepath.Dir(exe), "data")
		if err := os.MkdirAll(dir, 0o700); err == nil {
			return dir, nil
		}
	}
	dir := filepath.Join("data")
	return dir, os.MkdirAll(dir, 0o700)
}

func resolveBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("sing-box binary %q: %w", explicit, err)
		}
		return explicit, nil
	}
	names := []string{"sing-box.exe", "sing-box"}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, n := range names {
			candidates = append(candidates,
				filepath.Join(dir, n),
				filepath.Join(dir, "third_party", "sing-box", n),
			)
		}
	}
	if wd, err := os.Getwd(); err == nil {
		for _, n := range names {
			candidates = append(candidates,
				filepath.Join(wd, n),
				filepath.Join(wd, "third_party", "sing-box", n),
				filepath.Join(wd, "..", "third_party", "sing-box", n),
			)
		}
	}
	candidates = append(candidates,
		filepath.Join("third_party", "sing-box", "sing-box.exe"),
		filepath.Join("third_party", "sing-box", "sing-box"),
	)
	if runtime.GOOS != "windows" {
		candidates = append(candidates, "sing-box")
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
	return "", fmt.Errorf("sing-box not found (run scripts/fetch-sing-box.ps1)")
}
