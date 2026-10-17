package desync

import (
	"context"
	"net/netip"
	"os"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/proc"
)

// FailClass matches ByeDPI --auto triggers and contracts.md probe classes
// we surface to policy (timeout / ssl_err / reset).
type FailClass string

const (
	FailTimeout FailClass = "timeout"
	FailSSLErr  FailClass = "ssl_err"
	FailReset   FailClass = "reset"
	FailOK      FailClass = "ok"
)

// FailSignal is reported to policy when desync path fails for a target.
type FailSignal struct {
	Target     string    `json:"target"`
	Class      FailClass `json:"class"`
	StrategyID string    `json:"strategy_id"`
	Detail     string    `json:"detail,omitempty"`
	At         time.Time `json:"at"`
}

// Sink receives desync success/failure for policy / cascade.
type Sink interface {
	OnDesyncFail(sig FailSignal)
	OnDesyncOK(target, strategyID string)
}

// Strategy is one named ByeDPI argument group.
type Strategy struct {
	ID   string   // e.g. byedpi:windows-safe
	Args []string // flags after --ip/--port (no binary name)
	Note string
}

// Config controls the ByeDPI sidecar.
type Config struct {
	Context context.Context
	// BinaryPath is ciadpi (ciadpi.exe on Windows). Empty → Locate next to core.
	BinaryPath string
	// ListenIP defaults to 127.0.0.1.
	ListenIP string
	// ListenPort defaults to 18080 (avoid colliding with user SOCKS on 1080).
	ListenPort int
	// Strategy overrides the default safe set when non-empty Args.
	Strategy Strategy
	// AssignJob attaches the child to the engine Job Object (orphan kill).
	AssignJob func(*os.Process) error
	// Sink receives probe failure/success (optional).
	Sink Sink
	// Resolve looks up host via DoH (required when strategy uses --no-domain).
	Resolve func(ctx context.Context, host string) (netip.Addr, error)
	// ProbeHost is checked once after start (default discord.com). Empty skips.
	ProbeHost string
	// ProbeTimeout for TLS-via-SOCKS check.
	ProbeTimeout time.Duration
	// ConnIP binds ciadpi outbound sockets to the physical egress IPv4
	// (--conn-ip) so split-default TUN cannot loop dest SYNs back into Wintun.
	ConnIP string
	// BindInterface pins Darwin outbound sockets with IP_BOUND_IF so utun
	// cannot capture the proxy's own TCP/UDP traffic. The bundled Darwin build
	// consumes OFFVEIL_BIND_INTERFACE; other platforms ignore this field.
	BindInterface string
}

// DefaultConfig returns ByeDPI sidecar defaults.
func DefaultConfig() Config {
	return Config{
		ListenIP:     "127.0.0.1",
		ListenPort:   18080,
		Strategy:     NativeSafeStrategy(),
		ProbeHost:    "discord.com",
		ProbeTimeout: 8 * time.Second,
	}
}

// Info is runtime desync status for engine/status.
type Info struct {
	SocksAddr     string         `json:"socks_addr"`
	StrategyID    string         `json:"strategy_id"`
	BindInterface string         `json:"bind_interface,omitempty"`
	BinaryPath    string         `json:"binary_path,omitempty"`
	PID           int            `json:"pid,omitempty"`
	Up            bool           `json:"up"`
	LastProbe     FailClass      `json:"last_probe,omitempty"`
	LastProbeAt   string         `json:"last_probe_at,omitempty"`
	FailTimeouts  int            `json:"fail_timeouts"`
	FailSSLErrs   int            `json:"fail_ssl_errs"`
	FailResets    int            `json:"fail_resets"`
	Exit          *proc.ExitInfo `json:"exit,omitempty"`
	Checks        []FailSignal   `json:"checks,omitempty"`
}

// Session is a running ByeDPI SOCKS desync outbound.
type Session interface {
	Info() Info
	SocksAddr() string
	StrategyID() string
	// ProbeTLS dials host:443 via SOCKS and classifies the result.
	ProbeTLS(host string) FailSignal
	Close() error
}
