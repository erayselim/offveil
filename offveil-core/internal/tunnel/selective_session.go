package tunnel

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SelectiveSession is the 1.1 gateway. Group paths change at runtime through
// selectors, so a provider decision never recreates the TUN adapter.
type SelectiveSession interface {
	Session
	// SetGroupPath moves a group's TCP to desync/tunnel and its UDP to
	// direct/tunnel. Unknown groups and a missing tunnel are errors.
	SetGroupPath(ctx context.Context, group, path string) error
	GroupPaths() map[string]string
	TunnelAvailable() bool
	// StderrClass explains a stalled gateway without exporting its log.
	StderrClass() string
}

type selectiveSession struct {
	mu     sync.Mutex
	cfg    Config
	gw     *session
	paths  map[string]string
	groups map[string]bool
	closed bool
}

func startSelective(cfg Config) (Session, error) {
	if cfg.ProbeTimeout <= 0 || cfg.ProbeTimeout > 8*time.Second {
		cfg.ProbeTimeout = 8 * time.Second
	}
	provider := ProviderDesync
	switch cfg.TunnelProvider {
	case ProviderWARP:
		if cfg.WARPProfile == nil {
			return nil, &StartupError{Err: fmt.Errorf("tunnel requested without a verified WARP profile"),
				Failures: []ProviderFailure{{ProviderID: ProviderWARP, Stage: "configuration", Class: FailConfig}}}
		}
		provider = ProviderWARP
	case ProviderReality:
		reality, err := LoadRealityCredentials(cfg.Reality, cfg.DataDir)
		if err != nil || reality == nil {
			return nil, &StartupError{Err: fmt.Errorf("reality credentials unavailable"),
				Failures: []ProviderFailure{{ProviderID: ProviderReality, Stage: "configuration", Class: FailConfig}}}
		}
		cfg.Reality, provider = reality, ProviderReality
	}
	paths := map[string]string{}
	groups := map[string]bool{}
	for _, group := range cfg.Groups {
		groups[group.ID] = true
		paths[group.ID] = PathDesync
		if provider != ProviderDesync && cfg.GroupPaths[group.ID] == PathTunnel {
			paths[group.ID] = PathTunnel
		}
	}
	cfg.GroupPaths = paths
	if provider != ProviderDesync {
		control, err := newClashControl()
		if err != nil {
			return nil, &StartupError{Err: err, Failures: []ProviderFailure{{ProviderID: provider, Stage: "configuration", Class: FailConfig}}}
		}
		cfg.clash = control
	}
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	readiness, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cfg.startupContext = readiness
	gw, ok, class, err := startOne(cfg, providerAttempt{ID: provider, Reality: cfg.Reality})
	if !ok || gw == nil || !gw.Info().Up {
		failure := providerFailure(gw, provider, class, err)
		if failure.Stage == "" {
			failure.Stage = "gateway_startup"
		}
		if gw != nil {
			_ = gw.Close()
		}
		if err == nil {
			err = fmt.Errorf("gateway not ready")
		}
		return nil, &StartupError{Err: err, Failures: []ProviderFailure{failure}}
	}
	return &selectiveSession{cfg: cfg, gw: gw, paths: paths, groups: groups}, nil
}

func (s *selectiveSession) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	info := s.gw.Info()
	info.Mode, info.Coverage = "selective", "ipv4_web_desync"
	info.Selective = true
	info.Up = info.Up && !s.closed
	info.Healthy = info.Up
	info.TunnelAvailable = s.gw.provider != ProviderDesync
	info.GroupPaths = make(map[string]string, len(s.paths))
	for id, path := range s.paths {
		info.GroupPaths[id] = path
	}
	if s.cfg.WARPProfile != nil && info.TunnelAvailable {
		info.WARPEndpoint = s.cfg.WARPProfile.EndpointIPv4
	}
	if !info.Up {
		info.StderrClass = s.gw.stderrClass()
	}
	info.TunnelHosts, info.DirectHosts = nil, nil
	return info
}

func (s *selectiveSession) SocksAddr() string      { return s.gw.SocksAddr() }
func (s *selectiveSession) ProviderID() ProviderID { return s.gw.provider }
func (s *selectiveSession) StderrClass() string    { return s.gw.stderrClass() }

func (s *selectiveSession) ProbeTLS(host string) FailSignal {
	ctx := s.cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	return s.gw.probeTLSContext(ctx, host)
}

func (s *selectiveSession) TunnelAvailable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.gw.provider != ProviderDesync
}

func (s *selectiveSession) GroupPaths() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.paths))
	for id, path := range s.paths {
		out[id] = path
	}
	return out
}

func (s *selectiveSession) SetGroupPath(ctx context.Context, group, path string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return context.Canceled
	}
	if !s.groups[group] {
		s.mu.Unlock()
		return fmt.Errorf("unknown group %q", group)
	}
	if s.paths[group] == path {
		s.mu.Unlock()
		return nil
	}
	control, remote := s.cfg.clash, s.gw.provider != ProviderDesync
	s.mu.Unlock()
	if !remote || control == nil {
		return fmt.Errorf("no tunnel in this gateway")
	}
	udpPath := "direct"
	switch path {
	case PathTunnel:
		udpPath = PathTunnel
	case PathDesync:
	default:
		return fmt.Errorf("unknown path %q", path)
	}
	if err := control.selectOutbound(ctx, selectorTag(group, "tcp"), path); err != nil {
		return err
	}
	if err := control.selectOutbound(ctx, selectorTag(group, "udp"), udpPath); err != nil {
		// Keep TCP and UDP of one group on the same side.
		previous := PathDesync
		if path == PathDesync {
			previous = PathTunnel
		}
		_ = control.selectOutbound(context.Background(), selectorTag(group, "tcp"), previous)
		return err
	}
	s.mu.Lock()
	s.paths[group] = path
	s.mu.Unlock()
	return nil
}

func (s *selectiveSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return s.gw.Close()
}
