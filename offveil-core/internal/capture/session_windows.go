//go:build windows

package capture

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// session is the live Wintun + selected-route capture stack.
type session struct {
	mu sync.Mutex

	adapter   *wintun.Adapter
	wsession  wintun.Session
	luid      uint64
	tunPrefix netip.Prefix
	mtu       int
	dllPath   string
	snapshot  *Snapshot
	routes    []installedRoute
	allowlist []netip.Prefix
	closing   atomic.Bool
	drainDone chan struct{}
	// skipAdapter: sing-box owns Wintun; we only snapshot/resolve and optionally
	// attach later so AddPrefixes can install extra /32s.
	skipAdapter bool
}

// Start brings up Wintun, configures address, snapshots NICs, installs selected routes.
func Start(cfg Config) (Session, error) {
	dllPath, err := LocateDLL()
	if err != nil {
		return nil, fmt.Errorf("wintun dll: %w", err)
	}
	if err := ensureDLLLoadable(dllPath); err != nil {
		return nil, fmt.Errorf("wintun dll load prep: %w", err)
	}

	snap, err := TakeSnapshot()
	if err != nil {
		return nil, fmt.Errorf("adapter snapshot: %w", err)
	}
	if snap.Egress == nil {
		return nil, fmt.Errorf("no usable egress NIC (Wi-Fi/Ethernet with gateway)")
	}
	slog.Info("capture: egress selected",
		"name", snap.Egress.Name,
		"ifIndex", snap.Egress.IfIndex,
		"gateway", snap.Egress.Gateway,
		"adapters", len(snap.Adapters),
	)

	slog.Info("capture: resolving allowlist", "hosts", len(cfg.ResolveHosts), "skip_adapter", cfg.SkipAdapter)
	allow, err := BuildAllowlist(cfg)
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	if cfg.ApplyRoutes && !cfg.SkipAdapter && len(allow) == 0 {
		slog.Warn("capture: allowlist empty after resolve/exclude; adapter only")
	}

	if cfg.SkipAdapter {
		s := &session{
			tunPrefix:   netip.MustParsePrefix(TunIPv4),
			mtu:         cfg.MTU,
			snapshot:    snap,
			allowlist:   allow,
			drainDone:   make(chan struct{}),
			skipAdapter: true,
		}
		if s.mtu <= 0 {
			s.mtu = DefaultMTU
		}
		close(s.drainDone)
		slog.Info("capture: snapshot-only (sing-box owns TUN)", "routes_planned", len(allow))
		return s, nil
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	tunPrefix := netip.MustParsePrefix(TunIPv4)

	// Stable GUID so NLA does not spam a new network profile each start.
	guid := &windows.GUID{
		Data1: 0x0ff1e11,
		Data2: 0x0001,
		Data3: 0x4000,
		Data4: [8]byte{0x80, 0x00, 0x00, 0x0f, 0xf1, 0xe1, 0x00, 0x01},
	}

	adapter, err := wintun.CreateAdapter(AdapterName, TunnelType, guid)
	if err != nil {
		return nil, fmt.Errorf("WintunCreateAdapter: %w", err)
	}

	s := &session{
		adapter:   adapter,
		luid:      adapter.LUID(),
		tunPrefix: tunPrefix,
		mtu:       mtu,
		dllPath:   dllPath,
		snapshot:  snap,
		allowlist: allow,
		drainDone: make(chan struct{}),
	}

	rollback := func(cause error) error {
		_ = s.Close()
		return cause
	}

	if err := setTunIPv4(s.luid, tunPrefix, mtu); err != nil {
		return nil, rollback(fmt.Errorf("configure TUN IP: %w", err))
	}

	ws, err := adapter.StartSession(0x400000) // 4 MiB ring
	if err != nil {
		return nil, rollback(fmt.Errorf("WintunStartSession: %w", err))
	}
	s.wsession = ws

	// Drain only when this process owns the ring. sing-box dataplane uses SkipAdapter.
	go s.drainLoop()

	if cfg.ApplyRoutes {
		for _, p := range allow {
			ir, err := addSelectedRoute(s.luid, p)
			if err != nil {
				slog.Warn("capture: route add failed", "prefix", p.String(), "err", err)
				continue
			}
			s.routes = append(s.routes, ir)
		}
		slog.Info("capture: selected routes applied", "count", len(s.routes))
	}

	slog.Info("capture: up",
		"adapter", AdapterName,
		"luid", s.luid,
		"ipv4", tunPrefix.String(),
		"wintun", wintun.Version(),
		"dll", dllPath,
	)
	return s, nil
}

// AddPrefixes installs additional selected-route destinations (legacy CDN expand).
func (s *session) AddPrefixes(prefixes []netip.Prefix) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return 0, fmt.Errorf("capture: session closed")
	}
	if s.luid == 0 {
		if s.skipAdapter {
			luid, err := FindAdapterLUIDByName(AdapterName)
			if err != nil {
				return 0, err
			}
			s.luid = luid
		} else if s.adapter == nil {
			return 0, fmt.Errorf("capture: session closed")
		}
	}
	have := map[string]struct{}{}
	for _, r := range s.routes {
		have[r.dst.String()] = struct{}{}
	}
	added := 0
	var first error
	for _, p := range prefixes {
		if !p.IsValid() || !p.Addr().Is4() {
			continue
		}
		key := p.String()
		if _, ok := have[key]; ok {
			continue
		}
		ir, err := addSelectedRoute(s.luid, p)
		if err != nil {
			if first == nil {
				first = err
			}
			slog.Warn("capture: expand route failed", "prefix", key, "err", err)
			continue
		}
		s.routes = append(s.routes, ir)
		have[key] = struct{}{}
		added++
	}
	if added > 0 {
		slog.Info("capture: expand routes", "added", added, "total", len(s.routes))
	}
	return added, first
}

// AttachAdapter finds the live Wintun by friendly name (sing-box TUN).
func (s *session) AttachAdapter(name string) error {
	if name == "" {
		name = AdapterName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return fmt.Errorf("capture: session closed")
	}
	if !s.skipAdapter && s.adapter != nil && s.luid != 0 {
		return nil
	}
	luid, err := FindAdapterLUIDByName(name)
	if err != nil {
		return err
	}
	s.luid = luid
	slog.Info("capture: attached to dataplane adapter", "name", name, "luid", luid)
	return nil
}

func (s *session) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]struct{}{}
	prefixes := make([]string, 0, len(s.allowlist)+len(s.routes))
	for _, p := range s.allowlist {
		key := p.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		prefixes = append(prefixes, key)
	}
	for _, r := range s.routes {
		key := r.dst.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		prefixes = append(prefixes, key)
	}
	var eg *EgressInfo
	if s.snapshot != nil {
		eg = s.snapshot.Egress
	}
	ver := "sing-box"
	if !s.skipAdapter {
		ver = wintun.Version()
	}
	return Info{
		AdapterName:   AdapterName,
		LUID:          s.luid,
		IPv4:          s.tunPrefix.String(),
		MTU:           s.mtu,
		RoutesApplied: len(prefixes),
		RoutePrefixes: prefixes,
		Egress:        eg,
		WintunVersion: ver,
		DLLPath:       s.dllPath,
		Snapshot:      nil,
	}
}

func (s *session) Close() error {
	if !s.closing.CompareAndSwap(false, true) {
		return nil
	}
	s.mu.Lock()
	routes := append([]installedRoute(nil), s.routes...)
	s.routes = nil
	tun := s.tunPrefix
	luid := s.luid
	adapter := s.adapter
	skip := s.skipAdapter
	s.adapter = nil
	s.mu.Unlock()

	var first error
	if skip {
		// Extra /32s we added after attach; sing-box tears down its own auto_route.
		for _, r := range routes {
			if luid == 0 {
				break
			}
			if err := deleteSelectedRoute(luid, r); err != nil && first == nil {
				first = err
			}
		}
		slog.Info("capture: snapshot session down (dataplane adapter owned by sing-box)")
		return first
	}
	for _, r := range routes {
		if err := deleteSelectedRoute(luid, r); err != nil && first == nil {
			first = err
		}
	}
	if luid != 0 && tun.IsValid() {
		if err := clearTunIPv4(luid, tun); err != nil && first == nil {
			first = err
		}
	}

	// End session then close adapter (kills drain waiters).
	func() {
		defer func() { _ = recover() }()
		s.wsession.End()
	}()
	select {
	case <-s.drainDone:
	default:
		// drain may not have started
	}

	if adapter != nil {
		if err := adapter.Close(); err != nil && first == nil {
			first = err
		}
	}
	slog.Info("capture: down")
	return first
}

func (s *session) drainLoop() {
	defer close(s.drainDone)
	for !s.closing.Load() {
		pkt, err := s.wsession.ReceivePacket()
		if err != nil {
			return
		}
		s.wsession.ReleaseReceivePacket(pkt)
	}
}
