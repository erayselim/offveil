package tunnel

import "sync/atomic"

// FakeSession is an in-memory Session for unit tests (no sing-box / WARP).
type FakeSession struct {
	info   Info
	closed atomic.Bool
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
	return &FakeSession{info: info}
}

func (f *FakeSession) Info() Info               { return f.info }
func (f *FakeSession) SocksAddr() string        { return f.info.SocksAddr }
func (f *FakeSession) ProviderID() ProviderID   { return f.info.ProviderID }

func (f *FakeSession) ProbeTLS(host string) FailSignal {
	return FailSignal{Target: host, Class: FailOK, ProviderID: string(f.info.ProviderID)}
}

func (f *FakeSession) Close() error {
	f.closed.Store(true)
	f.info.Up = false
	return nil
}

func (f *FakeSession) Closed() bool { return f.closed.Load() }
