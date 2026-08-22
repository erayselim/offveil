package tunnel

import (
	"context"
	"net/netip"
	"os"
	"time"
)

// FailClass is reported when the selective tunnel path fails.
type FailClass string

const (
	FailOK      FailClass = "ok"
	FailTimeout FailClass = "timeout"
	FailDial    FailClass = "dial"
	FailAuth    FailClass = "auth" // register / handshake / config
	FailProbe   FailClass = "probe"
)

// FailSignal is reported to policy when tunnel path fails.
type FailSignal struct {
	Target     string    `json:"target"`
	Class      FailClass `json:"class"`
	ProviderID string    `json:"provider_id"`
	Detail     string    `json:"detail,omitempty"`
	At         time.Time `json:"at"`
}

// Sink receives tunnel success/failure for policy / cascade.
type Sink interface {
	OnTunnelFail(sig FailSignal)
	OnTunnelOK(target, providerID string)
}

// ProviderID names the active tunnel backend.
type ProviderID string

const (
	ProviderWARP    ProviderID = "warp"
	ProviderReality ProviderID = "reality"
	// ProviderDesync is sing-box TUN → local ByeDPI SOCKS (no WARP/Reality).
	ProviderDesync ProviderID = "desync"
)

// Config controls the selective tunnel outbound.
type Config struct {
	// BinaryPath is sing-box.exe. Empty → resolve next to offveil-core / third_party.
	BinaryPath string
	// ListenIP defaults to 127.0.0.1.
	ListenIP string
	// ListenPort defaults to 18081 (desync uses 18080).
	ListenPort int
	// DataDir stores WARP credentials (default: beside exe / data).
	DataDir string
	// PreferReality forces Reality first when credentials are available.
	PreferReality bool
	// Reality optional self-hosted VLESS+Reality (env / file override).
	Reality *RealityCredentials
	// Failover enables WARP ↔ Reality automatic retry. Nil/true = on.
	Failover *bool
	// AssignJob attaches the child to the engine Job Object.
	AssignJob func(*os.Process) error
	// Sink receives probe failure/success (optional). Final attempt only.
	Sink Sink
	// Resolve looks up host via DoH for probes / allowlist CIDRs.
	Resolve func(ctx context.Context, host string) (netip.Addr, error)
	// ProbeHost checked once after start (default discord.com). Empty skips.
	ProbeHost string
	// ProbeTimeout for TLS-via-SOCKS check.
	ProbeTimeout time.Duration
	// TunnelDomains override selective domain list (empty → DefaultTunnelDomains).
	TunnelDomains []string
	// DirectDomains override Steam/games DIRECT list (empty → DefaultDirectDomains).
	DirectDomains []string
	// SkipStart skips launching sing-box (unit tests / config-only).
	SkipStart bool

	// EnableTUN lets sing-box own Wintun + selected-route (contracts.md §6.1).
	// Go capture must not create a competing adapter when this is true.
	EnableTUN bool
	// TUNInterface is the Wintun adapter name (default capture.AdapterName).
	TUNInterface string
	// TUNAddress is the TUN IPv4 prefix (default 10.87.0.1/30).
	TUNAddress string
	// TUNMTU defaults to 1280.
	TUNMTU int
	// RouteCIDRs are selected-route prefixes (never 0.0.0.0/0). Required when EnableTUN.
	RouteCIDRs []string
	// ExcludeCIDRs are stripped from RouteCIDRs (WARP endpoint, public DNS, TUN subnet).
	ExcludeCIDRs []string
	// AllowlistOutbound is "desync" (ByeDPI SOCKS) or "tunnel" (WARP/Reality). Empty → tunnel.
	AllowlistOutbound string
	// DesyncSOCKS is ByeDPI listen addr (default 127.0.0.1:18080) when AllowlistOutbound=desync.
	DesyncSOCKS string
}

// DefaultConfig returns selective-tunnel defaults.
func DefaultConfig() Config {
	return Config{
		ListenIP:      "127.0.0.1",
		ListenPort:    18081,
		ProbeHost:     "discord.com",
		ProbeTimeout:  12 * time.Second,
		TunnelDomains: DefaultTunnelDomains(),
		DirectDomains: DefaultDirectDomains(),
	}
}

// Info is runtime tunnel status for engine/status.
type Info struct {
	SocksAddr      string       `json:"socks_addr"`
	ProviderID     ProviderID   `json:"provider_id"`
	BinaryPath     string       `json:"binary_path,omitempty"`
	ConfigPath     string       `json:"config_path,omitempty"`
	PID            int          `json:"pid,omitempty"`
	Up             bool         `json:"up"`
	Selective      bool         `json:"selective"` // never full-tunnel
	LastProbe      FailClass    `json:"last_probe,omitempty"`
	LastProbeAt    string       `json:"last_probe_at,omitempty"`
	RetryHint      bool         `json:"retry_hint,omitempty"` // UI: "yeniden dene" (all providers failed)
	FailDetail     string       `json:"fail_detail,omitempty"`
	TunnelHosts    []string     `json:"tunnel_hosts,omitempty"`
	DirectHosts    []string     `json:"direct_hosts,omitempty"`
	FailoverFrom   ProviderID   `json:"failover_from,omitempty"`   // previous provider if auto-switched
	ProvidersTried []ProviderID `json:"providers_tried,omitempty"`
}

// Session is a running selective tunnel outbound (sing-box SOCKS).
type Session interface {
	Info() Info
	SocksAddr() string
	ProviderID() ProviderID
	ProbeTLS(host string) FailSignal
	Close() error
}
