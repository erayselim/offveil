package capture

import "net/netip"

// FakeSession is an in-memory Session for unit tests (no Wintun).
type FakeSession struct {
	info   Info
	closed bool
	seen   map[string]struct{}
}

func NewFakeSession(info Info) *FakeSession {
	if info.AdapterName == "" {
		info.AdapterName = AdapterName
	}
	seen := map[string]struct{}{}
	for _, p := range info.RoutePrefixes {
		seen[p] = struct{}{}
	}
	return &FakeSession{info: info, seen: seen}
}

func (f *FakeSession) Info() Info { return f.info }

func (f *FakeSession) Close() error {
	f.closed = true
	return nil
}

func (f *FakeSession) Closed() bool { return f.closed }

func (f *FakeSession) AttachAdapter(name string) error {
	if name != "" {
		f.info.AdapterName = name
	}
	if f.info.LUID == 0 {
		f.info.LUID = 1
	}
	return nil
}

func (f *FakeSession) AddPrefixes(prefixes []netip.Prefix) (int, error) {
	if f.closed {
		return 0, nil
	}
	if f.seen == nil {
		f.seen = map[string]struct{}{}
	}
	added := 0
	for _, p := range prefixes {
		if !p.IsValid() || !p.Addr().Is4() {
			continue
		}
		key := p.String()
		if _, ok := f.seen[key]; ok {
			continue
		}
		f.seen[key] = struct{}{}
		f.info.RoutePrefixes = append(f.info.RoutePrefixes, key)
		f.info.RoutesApplied = len(f.info.RoutePrefixes)
		added++
	}
	return added, nil
}
