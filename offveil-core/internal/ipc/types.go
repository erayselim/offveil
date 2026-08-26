package ipc

// Request is the UI → core JSON envelope (docs/contracts.md §2.1).
type Request struct {
	ID     string         `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

// Response is the core → UI JSON envelope.
type Response struct {
	ID     string    `json:"id"`
	OK     bool      `json:"ok"`
	Result any       `json:"result,omitempty"`
	Error  *RPCError `json:"error,omitempty"`
}

// RPCError matches contracts.md error shape.
type RPCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Status is contracts.md §2.3.
type Status struct {
	State        string         `json:"state"`
	Protection   bool           `json:"protection"`
	Summary      string         `json:"summary"`
	OutboundHint string         `json:"outbound_hint,omitempty"`
	Since        *string        `json:"since"`
	Targets      []TargetStatus `json:"targets"`
	LastError    *string        `json:"last_error"`
	Health       string         `json:"health"`
	Version      string         `json:"version,omitempty"`
	ContractsVer int            `json:"contracts_version,omitempty"`
	// Capture is TUN diagnostics (optional; UI may ignore).
	Capture any `json:"capture,omitempty"`
	// DNS is DoH stub / leak-guard diagnostics.
	DNS any `json:"dns,omitempty"`
	// Desync is ByeDPI SOCKS outbound diagnostics.
	Desync any `json:"desync,omitempty"`
	// Tunnel is selective WARP/Reality outbound diagnostics.
	Tunnel any `json:"tunnel,omitempty"`
	// Ruleset is signed package diagnostics (optional; UI may ignore).
	Ruleset any `json:"ruleset,omitempty"`
	// Expand is legacy CDN / half-load domain expansion (optional).
	Expand any `json:"expand,omitempty"`
	// UDP is Discord voice UDP path + QUIC policy (optional; UI may ignore).
	UDP any `json:"udp,omitempty"`
	// Heal is network-change / power-resume self-heal (optional; UI may ignore).
	Heal any `json:"heal,omitempty"`
}

// TargetStatus is one curated package outcome.
type TargetStatus struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Outcome string `json:"outcome"`
	Path    string `json:"path"`
}

// PingResult is the ping method result.
type PingResult struct {
	Version          string `json:"version"`
	ContractsVersion int    `json:"contracts_version"`
	Service          string `json:"service"`
}

// TestReport is contracts.md §4.3 (connection test).
type TestReport struct {
	ASN     string       `json:"asn"`
	ISPHint string       `json:"isp_hint,omitempty"`
	Results []TestResult `json:"results"`
}

// TestResult is one target row in TestReport.
type TestResult struct {
	Target string `json:"target"`
	Class  string `json:"class"`
	Path   string `json:"path"`
	OK     bool   `json:"ok"`
}

// DiagnosticsBundle is contracts.md §2.2 diagnostics result.
type DiagnosticsBundle struct {
	Path      string `json:"path"`
	CreatedAt string `json:"created_at"`
	SHA256    string `json:"sha256"`
	Version   string `json:"version"`
	Note      string `json:"note,omitempty"`
}

// RepairResult is contracts.md §2.2 repair / "Revert changes".
type RepairResult struct {
	Status *Status      `json:"status"`
	Steps  []RepairStep `json:"steps,omitempty"`
}

// RepairStep is one best-effort restore action.
type RepairStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Error codes from contracts.md §2.4.
const (
	CodeNotRunning     = "not_running"
	CodeAlreadyRunning = "already_running"
	CodePrivilege      = "privilege"
	CodeTunFailed      = "tun_failed"
	CodeEngineFailed   = "engine_failed"
	CodeInternal       = "internal"
	CodeBadRequest     = "bad_request"
)
