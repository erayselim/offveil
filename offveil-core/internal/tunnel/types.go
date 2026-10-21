package tunnel

import (
	"context"
	"net/netip"
	"os"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/proc"
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
)

// FailClass is reported when the selective tunnel path fails.
type FailClass string

const (
	FailOK          FailClass = "ok"
	FailTimeout     FailClass = "timeout"
	FailDial        FailClass = "dial"
	FailAuth        FailClass = "auth" // register / handshake / config
	FailProbe       FailClass = "probe"
	FailEOF         FailClass = "eof"
	FailReset       FailClass = "reset"
	FailRefused     FailClass = "refused"
	FailCertificate FailClass = "certificate"
	FailConfig      FailClass = "config"
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
	Context context.Context
	// NetworkMode routes public traffic by transport, without application identities.
	NetworkMode   bool
	NetworkRoutes []ruleset.RouteRule
	// ControlHosts are independent TLS controls; at least two must pass.
	ControlHosts  []string
	ControlQuorum int
	// ProviderListenPort is the private, TUN-free provider verification listener.
	ProviderListenPort int
	// providerOnly and upstreamSOCKS are internal parts of the single-gateway topology.
	providerOnly   bool
	upstreamSOCKS  string
	startupContext context.Context
	// BinaryPath is sing-box (sing-box.exe on Windows). Empty → Locate next to core.
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
	// ProbeHost is a legacy explicit target check. NetworkMode uses ControlHosts instead.
	ProbeHost string
	// ProbeTimeout for TLS-via-SOCKS check.
	ProbeTimeout time.Duration
	// TunnelDomains are legacy explicit routing suffixes.
	TunnelDomains []string
	// SpecialDomains are legacy explicit UDP routing suffixes.
	SpecialDomains []string
	// DirectDomains are legacy explicit direct routes.
	DirectDomains    []string
	ProtectedDomains []string
	// SkipStart skips launching sing-box (unit tests / config-only).
	SkipStart bool

	// EnableTUN lets sing-box own the TUN (contracts.md §6.1).
	// Go capture must not create a competing adapter when this is true.
	EnableTUN bool
	// TUNInterface is the Wintun adapter name on Windows (default capture.AdapterName).
	// Darwin omits it so sing-box selects utunN.
	TUNInterface string
	// TUNAddress is the TUN IPv4 prefix (default 10.87.0.1/30).
	TUNAddress  string
	TUNAddress6 string
	// TUNMTU defaults to 1280.
	TUNMTU int
	// RouteCIDRs are TUN prefixes (never 0.0.0.0/0). Empty + EnableTUN → split-default.
	RouteCIDRs []string
	// ExcludeCIDRs are stripped from RouteCIDRs (WARP endpoint, public DNS, TUN subnet).
	ExcludeCIDRs []string
	// AllowlistOutbound is "desync" (ByeDPI SOCKS) or "tunnel" (WARP/Reality). Empty → tunnel.
	AllowlistOutbound string
	// DesyncSOCKS is ByeDPI listen addr (default 127.0.0.1:18080) when AllowlistOutbound=desync.
	DesyncSOCKS string
	// EgressInterface is the physical NIC selected before installing TUN routes.
	EgressInterface string
	// DNSAddress is the already-running core DNS stub. Only loopback literals
	// are accepted; empty retains standalone DoH for isolated sidecar use.
	DNSAddress string
}

// DefaultConfig returns selective-tunnel defaults.
func DefaultConfig() Config {
	return Config{
		ListenIP:      "127.0.0.1",
		ListenPort:    18081,
		ProbeTimeout:  12 * time.Second,
		TunnelDomains: DefaultTunnelDomains(),
		DirectDomains: DefaultDirectDomains(),
	}
}

// ProviderFailure retains allowlisted facts from an exhausted provider attempt.
type ProviderFailure struct {
	ProviderID ProviderID      `json:"provider_id"`
	Class      FailClass       `json:"class"`
	Reason     string          `json:"reason,omitempty"`
	Exit       *proc.ExitInfo  `json:"exit,omitempty"`
	Stage      string          `json:"stage,omitempty"`
	Target     string          `json:"target,omitempty"`
	ExitOrigin string          `json:"exit_origin,omitempty"`
	Controls   []ControlResult `json:"controls,omitempty"`
}

// ControlResult is a certificate-verified TLS result, never an application probe.
type ControlResult struct {
	Target string    `json:"target"`
	Class  FailClass `json:"class"`
	At     string    `json:"at"`
}

// Info is runtime tunnel status for engine/status.
type Info struct {
	Mode            string            `json:"mode,omitempty"`
	Coverage        string            `json:"coverage,omitempty"`
	Healthy         bool              `json:"healthy"`
	ControlQuorum   int               `json:"control_quorum,omitempty"`
	Controls        []ControlResult   `json:"controls,omitempty"`
	GatewayControls []ControlResult   `json:"gateway_controls,omitempty"`
	ProviderPID     int               `json:"provider_pid,omitempty"`
	SocksAddr       string            `json:"socks_addr"`
	ProviderID      ProviderID        `json:"provider_id"`
	BinaryPath      string            `json:"binary_path,omitempty"`
	ConfigPath      string            `json:"config_path,omitempty"`
	PID             int               `json:"pid,omitempty"`
	Exit            *proc.ExitInfo    `json:"exit,omitempty"`
	Up              bool              `json:"up"`
	Selective       bool              `json:"selective"` // never full-tunnel
	LastProbe       FailClass         `json:"last_probe,omitempty"`
	LastProbeAt     string            `json:"last_probe_at,omitempty"`
	RetryHint       bool              `json:"retry_hint,omitempty"` // UI: "yeniden dene" (all providers failed)
	FailDetail      string            `json:"fail_detail,omitempty"`
	TunnelHosts     []string          `json:"tunnel_hosts,omitempty"`
	DirectHosts     []string          `json:"direct_hosts,omitempty"`
	FailoverFrom    ProviderID        `json:"failover_from,omitempty"` // previous provider if auto-switched
	ProvidersTried  []ProviderID      `json:"providers_tried,omitempty"`
	Failures        []ProviderFailure `json:"failures,omitempty"`
	EgressInterface string            `json:"egress_interface,omitempty"`
	TUNStack        string            `json:"tun_stack,omitempty"`
	TUNMTU          int               `json:"tun_mtu,omitempty"`
	StartupAttempts int               `json:"startup_attempts,omitempty"`
	DNSMode         string            `json:"dns_mode,omitempty"`
}

// Session is a running selective tunnel outbound (sing-box SOCKS).
type Session interface {
	Info() Info
	SocksAddr() string
	ProviderID() ProviderID
	ProbeTLS(host string) FailSignal
	Close() error
}
