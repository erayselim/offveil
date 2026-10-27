package tunnel

import (
	"context"
	"errors"
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

	"github.com/erayselim/offveil/offveil-core/internal/proc"
	"github.com/erayselim/offveil/offveil-core/internal/sidecar"
)

type session struct {
	mu sync.Mutex

	cfg        Config
	child      *proc.Child
	socks      string
	provider   ProviderID
	configPath string
	binPath    string

	up              atomic.Bool
	retryHint       atomic.Bool
	failDetail      atomic.Value // string
	lastProbe       atomic.Value // FailClass
	lastProbeAt     atomic.Value // string
	failoverFrom    ProviderID
	providersTried  []ProviderID
	failures        []ProviderFailure
	startupAttempts int
	peerExclusions  []string
	controls        []ControlResult
	controlHealthy  bool
	exitOrigin      string
	stderr          *proc.TailBuffer
}

// stderrClass classifies the live log tail without exporting it.
func (s *session) stderrClass() string {
	s.mu.Lock()
	tail := s.stderr
	s.mu.Unlock()
	if tail == nil {
		return ""
	}
	class, reason := proc.ClassifyStderr(tail.String())
	if reason != "" {
		return reason
	}
	return class
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
	if !cfg.NetworkMode && !cfg.EnableTUN && len(cfg.TunnelDomains) == 0 {
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
	if cfg.Selective {
		return startSelective(cfg)
	}
	if cfg.NetworkMode {
		return nil, fmt.Errorf("full-network gateway was removed; use Selective")
	}

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
		failures   []ProviderFailure
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
			s.failures = append([]ProviderFailure(nil), failures...)
			if cfg.Sink != nil && cfg.ProbeHost != "" {
				info := s.Info()
				if info.LastProbe == FailOK || info.LastProbe == "" {
					cfg.Sink.OnTunnelOK(cfg.ProbeHost, string(attempt.ID))
				}
			}
			return s, nil
		}
		prevFailed = attempt.ID
		failure := providerFailure(s, attempt.ID, failClass, failErr)
		failures = append(failures, failure)
		slog.Warn("tunnel: provider failed, trying next",
			"provider", attempt.ID,
			"class", failClass,
			"err", failErr,
			"remaining", len(order)-i-1,
		)
		if s != nil {
			_ = s.Close()
		}
		lastFail = softFailSession(cfg, attempt.ID, failClass, failErr, tried, prevFailed)
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
	final, err := failSession(cfg, order[len(order)-1].ID, class, fmt.Errorf("%s", detail), tried, prevFailed)
	final.(*session).failures = failures
	return final, err
}

// Only stable reason codes enter support data; never provider responses or URLs.
func providerFailureReason(err error) string {
	var status *warpHTTPError
	if errors.As(err, &status) {
		return fmt.Sprintf("http_%d", status.code)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	return ""
}

// startOne launches one provider. ok=false means try next (or final fail).
// Does not call Sink - Start owns policy notifications.
func startOne(cfg Config, attempt providerAttempt) (s *session, ok bool, class FailClass, err error) {
	provider := attempt.ID
	reality := attempt.Reality
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	startup := cfg.startupContext
	if startup == nil {
		startup = ctx
	}

	var warp *WARPProfile
	if provider == ProviderWARP && cfg.WARPProfile != nil {
		warp = cfg.WARPProfile
	} else if provider == ProviderWARP && cfg.upstreamSOCKS == "" {
		client := newBootstrapHTTPClient(cfg)
		defer client.CloseIdleConnections()
		_, warp, err = loadOrRegisterWARP(startup, cfg.DataDir, client)
		if err != nil {
			return nil, false, FailAuth, stageError("registration", "", err)
		}
	}

	build, err := BuildSingBox(buildParamsFrom(cfg, provider, warp, reality))
	if err != nil {
		return nil, false, FailConfig, stageError("configuration", "", err)
	}

	// Background provider changes may finish after Stop/new Start. Each launch
	// owns a distinct configuration so a late write cannot replace a new one's.
	configFile, err := os.CreateTemp(cfg.DataDir, "sing-box-*.json")
	if err != nil {
		return nil, false, FailConfig, stageError("configuration_write", "", err)
	}
	cfgPath := configFile.Name()
	keepConfig := false
	defer func() {
		if !keepConfig {
			_ = os.Remove(cfgPath)
		}
	}()
	_, writeErr := configFile.Write(build.JSON)
	closeErr := configFile.Close()
	if writeErr != nil {
		return nil, false, FailConfig, stageError("configuration_write", "", writeErr)
	}
	if closeErr != nil {
		return nil, false, FailConfig, stageError("configuration_write", "", closeErr)
	}
	if err := ctx.Err(); err != nil {
		return nil, false, FailAuth, err
	}

	s = &session{
		cfg:            cfg,
		socks:          net.JoinHostPort(cfg.ListenIP, strconv.Itoa(cfg.ListenPort)),
		provider:       provider,
		configPath:     cfgPath,
		peerExclusions: networkPeerExclusions(warp, reality),
	}
	s.lastProbe.Store(FailClass(""))
	s.lastProbeAt.Store("")
	s.failDetail.Store("")

	if cfg.SkipStart {
		keepConfig = true
		s.up.Store(true)
		s.lastProbe.Store(FailOK)
		return s, true, FailOK, nil
	}

	bin, err := resolveBinary(cfg.BinaryPath)
	if err != nil {
		return nil, false, FailDial, stageError("binary", "", err)
	}
	s.binPath = bin

	if cfg.EnableTUN {
		if err := ensureWintunBeside(bin); err != nil {
			return nil, false, FailDial, stageError("adapter", "", err)
		}
	}

	s.child, s.startupAttempts, err = startWithTUNRetry(startup, cfg.EnableTUN && runtime.GOOS == "windows", func(readiness context.Context) (*proc.Child, error) {
		// The process belongs to the protection session, not the readiness deadline.
		cmd := exec.CommandContext(ctx, bin, "run", "-c", cfgPath)
		stderr := &proc.TailBuffer{}
		s.mu.Lock()
		s.stderr = stderr
		s.mu.Unlock()
		cmd.Stdout = nil
		cmd.Stderr = stderr
		proc.PrepareCmd(cmd)
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("sing-box start: %w", err)
		}
		if cfg.AssignJob != nil && cmd.Process != nil {
			if err := cfg.AssignJob(cmd.Process); err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return nil, fmt.Errorf("assign job: %w", err)
			}
		}
		child := proc.WatchChild(cmd)
		if err := proc.WaitTCPContext(readiness, s.socks, 8*time.Second, child); err != nil {
			s.exitOrigin = "cleanup"
			if !child.Running() {
				s.exitOrigin = "natural"
			}
			child.Close()
			return child, fmt.Errorf("socks not ready: %w; stderr: %s", err, stderr.String())
		}
		return child, nil
	})
	if err != nil {
		return s, false, FailDial, stageError("startup", "", err)
	}
	s.up.Store(true)
	keepConfig = true
	slog.Info("tunnel: selective outbound up",
		"provider", provider,
		"socks", s.socks,
		"pid", s.child.PID(),
		"selective", true,
	)

	if cfg.NetworkMode && cfg.providerOnly {
		results, healthy := checkControls(startup, cfg.ControlHosts, cfg.ControlQuorum, s.probeTLSContext)
		s.controls, s.controlHealthy = results, healthy
		if !healthy {
			s.exitOrigin = "cleanup"
			if !s.child.Running() {
				s.exitOrigin = "natural"
			}
			_ = s.Close()
			class, target := FailProbe, ""
			for _, result := range results {
				if result.Class != FailOK {
					class, target = result.Class, result.Target
					break
				}
			}
			return s, false, class, stageError("control_tls", target, fmt.Errorf("control quorum unavailable"))
		}
		s.lastProbe.Store(FailOK)
	} else if cfg.ProbeHost != "" && !cfg.NetworkMode {
		if IsDirectHost(cfg.ProbeHost, cfg.DirectDomains) {
			slog.Warn("tunnel: probe host is on DIRECT list; skipping", "host", cfg.ProbeHost)
			s.lastProbe.Store(FailOK)
			return s, true, FailOK, nil
		}
		sig := s.ProbeTLS(cfg.ProbeHost)
		if sig.Class != FailOK {
			detail := sig.Detail
			s.exitOrigin = "cleanup"
			if !s.child.Running() {
				s.exitOrigin = "natural"
			}
			_ = s.Close()
			return s, false, sig.Class, stageError("target_tls", cfg.ProbeHost, fmt.Errorf("probe: %s", detail))
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
		Healthy:         s.controlHealthy,
		Controls:        append([]ControlResult(nil), s.controls...),
		ControlQuorum:   s.cfg.ControlQuorum,
		SocksAddr:       s.socks,
		ProviderID:      s.provider,
		BinaryPath:      s.binPath,
		ConfigPath:      s.configPath,
		Up:              s.isUp(),
		Exit:            s.child.Exit(),
		Selective:       true,
		RetryHint:       s.retryHint.Load(),
		TunnelHosts:     s.cfg.TunnelDomains,
		DirectHosts:     s.cfg.DirectDomains,
		FailoverFrom:    s.failoverFrom,
		ProvidersTried:  append([]ProviderID(nil), s.providersTried...),
		Failures:        append([]ProviderFailure(nil), s.failures...),
		EgressInterface: s.cfg.EgressInterface,
		StartupAttempts: s.startupAttempts,
	}
	if s.cfg.EnableTUN {
		info.TUNStack = tunStack()
		info.TUNMTU = s.cfg.TUNMTU
		if info.TUNMTU <= 0 {
			info.TUNMTU = defaultTUNMTU
		}
	}
	info.DNSMode = "standalone_doh"
	if s.cfg.DNSAddress != "" {
		info.DNSMode = "core_stub"
	}
	if s.child != nil {
		info.PID = s.child.PID()
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
	if s.child == nil {
		if s.configPath != "" {
			_ = os.Remove(s.configPath)
		}
		return nil
	}
	s.child.Close()
	if s.configPath != "" {
		_ = os.Remove(s.configPath)
	}
	slog.Info("tunnel: stopped", "socks", s.socks)
	return nil
}

func (s *session) recordProbe(sig FailSignal) {
	s.lastProbe.Store(sig.Class)
	s.lastProbeAt.Store(sig.At.UTC().Format(time.RFC3339))
	if sig.Class != FailOK {
		s.retryHint.Store(true)
		s.failDetail.Store(sig.Detail)
	} else {
		s.retryHint.Store(false)
		s.failDetail.Store("")
	}
}

func (s *session) isUp() bool {
	return s.up.Load() && (s.child == nil || s.child.Running())
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
		NetworkMode:       cfg.NetworkMode,
		ProviderOnly:      cfg.providerOnly,
		NetworkRoutes:     cfg.NetworkRoutes,
		UpstreamSOCKS:     cfg.upstreamSOCKS,
		Provider:          provider,
		WARP:              warp,
		Reality:           reality,
		ListenIP:          cfg.ListenIP,
		ListenPort:        cfg.ListenPort,
		TunnelDomains:     cfg.TunnelDomains,
		SpecialDomains:    cfg.SpecialDomains,
		DirectDomains:     cfg.DirectDomains,
		ProtectedDomains:  cfg.ProtectedDomains,
		EnableTUN:         cfg.EnableTUN,
		TUNInterface:      iface,
		TUNAddress:        addr,
		TUNAddress6:       cfg.TUNAddress6,
		TUNMTU:            cfg.TUNMTU,
		RouteCIDRs:        append([]string{}, cfg.RouteCIDRs...),
		ExcludeCIDRs:      append([]string{}, cfg.ExcludeCIDRs...),
		AllowlistOutbound: cfg.AllowlistOutbound,
		EgressInterface:   cfg.EgressInterface,
		DesyncSOCKSHost:   host,
		DesyncSOCKSPort:   port,
		DNSAddress:        cfg.DNSAddress,

		Selective:          cfg.Selective,
		Groups:             cfg.Groups,
		GroupPaths:         cfg.GroupPaths,
		ExcludeSuffixes:    cfg.ExcludeSuffixes,
		QuicRejectSuffixes: cfg.QuicRejectSuffixes,
		ClashController:    cfg.clash.address(),
		ClashSecret:        cfg.clash.token(),
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
	return proc.WaitTCP(addr, timeout, nil)
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
	return sidecar.Locate(sidecar.SingBox)
}
