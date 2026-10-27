package tunnel

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// FakeSession is an in-memory Session for unit tests (no sing-box / WARP).
// It also implements SelectiveSession so engine tests can drive group paths.
type FakeSession struct {
	info   Info
	closed atomic.Bool

	mu        sync.Mutex
	probe     func(host, path string) FailClass
	paths     map[string]string
	hostGroup map[string]string
	moves     []string
}

// WithHostGroups tells ProbeTLS which group path applies to a probe host.
func (f *FakeSession) WithHostGroups(hostGroup map[string]string) *FakeSession {
	f.mu.Lock()
	f.hostGroup = hostGroup
	for _, group := range hostGroup {
		if _, ok := f.paths[group]; !ok {
			f.paths[group] = PathDesync
		}
	}
	f.mu.Unlock()
	return f
}

// NewFakeSession returns a no-op tunnel session.
func NewFakeSession(info Info) *FakeSession {
	if info.SocksAddr == "" {
		info.SocksAddr = "127.0.0.1:18081"
	}
	if info.ProviderID == "" {
		info.ProviderID = ProviderWARP
	}
	info.Selective = true
	paths := map[string]string{}
	for id, path := range info.GroupPaths {
		paths[id] = path
	}
	return &FakeSession{info: info, paths: paths}
}

// WithProbe makes ProbeTLS depend on the host and the host's current group path.
func (f *FakeSession) WithProbe(fn func(host, path string) FailClass) *FakeSession {
	f.mu.Lock()
	f.probe = fn
	f.mu.Unlock()
	return f
}

func (f *FakeSession) Info() Info {
	info := f.info
	info.Up = info.Up && !f.closed.Load()
	info.GroupPaths = f.GroupPaths()
	return info
}
func (f *FakeSession) SocksAddr() string      { return f.info.SocksAddr }
func (f *FakeSession) ProviderID() ProviderID { return f.info.ProviderID }
func (f *FakeSession) StderrClass() string    { return f.info.StderrClass }

func (f *FakeSession) ProbeTLS(host string) FailSignal {
	f.mu.Lock()
	probe := f.probe
	path := f.paths[f.hostGroup[host]]
	f.mu.Unlock()
	class := FailOK
	if probe != nil {
		class = probe(host, path)
	}
	return FailSignal{Target: host, Class: class, ProviderID: string(f.info.ProviderID)}
}

func (f *FakeSession) TunnelAvailable() bool { return f.info.TunnelAvailable && !f.closed.Load() }

func (f *FakeSession) GroupPaths() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]string, len(f.paths))
	for id, path := range f.paths {
		out[id] = path
	}
	return out
}

func (f *FakeSession) SetGroupPath(_ context.Context, group, path string) error {
	if !f.TunnelAvailable() {
		return fmt.Errorf("no tunnel in this gateway")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.paths[group]; !ok {
		return fmt.Errorf("unknown group %q", group)
	}
	f.paths[group] = path
	f.moves = append(f.moves, group+"="+path)
	return nil
}

// Moves lists SetGroupPath calls in order.
func (f *FakeSession) Moves() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.moves...)
}

func (f *FakeSession) Close() error {
	f.closed.Store(true)
	return nil
}

func (f *FakeSession) Closed() bool { return f.closed.Load() }
