//go:build darwin

package dns

import "log/slog"

type nrptGuard struct {
	applied bool
}

func newNRPTGuard(stubHost string, domains []string) (*nrptGuard, error) {
	if len(NRPTNamespaces(domains)) == 0 {
		return &nrptGuard{}, nil
	}
	host, _, err := splitHostPortDefault(stubHost, "53")
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = stubDNSIP
	}
	if err := applySystemDNSWith(liveSystemDNS(), host); err != nil {
		return nil, err
	}
	slog.Info("dns: networksetup applied", "stub", host)
	return &nrptGuard{applied: true}, nil
}

func (g *nrptGuard) Close() error {
	if g == nil || !g.applied {
		return nil
	}
	g.applied = false
	_, err := restoreSystemDNSWith(liveSystemDNS(), true, false)
	return err
}

// NRPTPresent is true when a Darwin snapshot exists or a target service
// still points at 127.0.0.1 (leftover after crash).
func NRPTPresent() bool {
	return leftoverStubPresent(liveSystemDNS())
}

// RemoveNRPT restores networksetup DNS from the snapshot or empty.
func RemoveNRPT() error {
	_, err := restoreSystemDNSWith(liveSystemDNS(), true, false)
	return err
}

// FlushResolverCache is killall -HUP mDNSResponder (Windows DnsFlushResolverCache).
func FlushResolverCache() {
	_ = liveSystemDNS().Flush()
}

func reloadDNSClient() { FlushResolverCache() }
