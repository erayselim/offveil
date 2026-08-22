package dns

import (
	"fmt"
	"net"
	"net/netip"
)

// PoisonError is returned when a resolution yields a known censorship fingerprint.
type PoisonError struct {
	Host  string
	Addr  netip.Addr
	ID    string
	Via   string
	Class string // contracts.md: dns_poison
}

func (e *PoisonError) Error() string {
	return fmt.Sprintf("dns_poison host=%s addr=%s fingerprint=%s via=%s", e.Host, e.Addr, e.ID, e.Via)
}

// QueryObserver is called for each stub question name (domain expand).
// Must not block; engine runs expand work asynchronously.
type QueryObserver func(host string)

// Config controls the DNS protection stack.
type Config struct {
	// ListenAddr is the stub bind address (default 127.0.0.1:53).
	ListenAddr string
	// ApplyLeakGuard rewrites TUN (+ egress) DNS to the stub and restores on Close.
	// Default false: rewriting the physical NIC to 127.0.0.1 surprises users and
	// is unnecessary once NRPT covers allowlist suffixes.
	ApplyLeakGuard bool
	// TunLUID is the offveil Wintun LUID (required when ApplyLeakGuard).
	TunLUID uint64
	// EgressLUID is the physical NIC LUID to pin away from ISP DNS (optional).
	EgressLUID uint64
	// NRPTSuffixes installs Windows Name Resolution Policy for these domains
	// (apex + suffix) pointing at the local DoH stub - without changing ipconfig DNS.
	NRPTSuffixes []string
	// OnQuery observes client lookups for legacy CDN auto-expand (optional).
	OnQuery QueryObserver
}

// DefaultConfig returns DoH stub defaults.
func DefaultConfig() Config {
	return Config{
		ListenAddr:     "127.0.0.1:53",
		ApplyLeakGuard: false,
	}
}

// Info is runtime DNS status for engine/status.
type Info struct {
	ListenAddr     string   `json:"listen_addr"`
	DoHEndpoints   []string `json:"doh_endpoints,omitempty"`
	StubUp         bool     `json:"stub_up"`
	LeakGuard      bool     `json:"leak_guard"`
	NRPT           bool     `json:"nrpt,omitempty"`
	PoisonHits     int      `json:"poison_hits"`
	Queries        uint64   `json:"queries"`
	PlainFallbacks uint64   `json:"plain_fallbacks"`
	DoHMode        string   `json:"doh_mode,omitempty"` // doh | plain_skip | recovering
	LastPoisonID   string   `json:"last_poison_id,omitempty"`
	LastPoisonHost string   `json:"last_poison_host,omitempty"`
}

// Session is an active DoH stub + optional leak-guard.
type Session interface {
	Info() Info
	Client() *DoHClient
	Close() error
}

// ProbeSystemDNS resolves host via the OS resolver and checks poison fingerprints.
// Used for diagnostics / probe class dns_poison (contracts.md §4).
func ProbeSystemDNS(host string, poison *PoisonSet) (addrs []netip.Addr, poisonID string, err error) {
	if poison == nil {
		poison = DefaultPoisonSet()
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, "", err
	}
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		addr := netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
		addrs = append(addrs, addr)
		if id, hit := poison.Match(addr); hit {
			return addrs, id, nil
		}
	}
	return addrs, "", nil
}
