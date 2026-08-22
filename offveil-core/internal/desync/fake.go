package desync

import "sync/atomic"

// FakeSession is an in-memory Session for unit tests (no ciadpi).
type FakeSession struct {
	info   Info
	closed atomic.Bool
}

// NewFakeSession returns a no-op desync session.
func NewFakeSession(info Info) *FakeSession {
	if info.SocksAddr == "" {
		info.SocksAddr = "127.0.0.1:18080"
	}
	if info.StrategyID == "" {
		info.StrategyID = DefaultSafeStrategy().ID
	}
	info.Up = true
	return &FakeSession{info: info}
}

func (f *FakeSession) Info() Info         { return f.info }
func (f *FakeSession) SocksAddr() string  { return f.info.SocksAddr }
func (f *FakeSession) StrategyID() string { return f.info.StrategyID }

func (f *FakeSession) ProbeTLS(host string) FailSignal {
	class := FailOK
	if f.info.LastProbe != "" {
		class = f.info.LastProbe
	}
	return FailSignal{Target: host, Class: class, StrategyID: f.info.StrategyID}
}

func (f *FakeSession) Close() error {
	f.closed.Store(true)
	f.info.Up = false
	return nil
}

func (f *FakeSession) Closed() bool { return f.closed.Load() }
