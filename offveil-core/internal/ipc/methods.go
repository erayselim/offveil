package ipc

import "encoding/json"

// MaxRequestBytes caps a single pipe connection's JSON traffic.
const MaxRequestBytes = 64 * 1024

func paramsBytes(params map[string]any) int {
	if params == nil {
		return 0
	}
	b, err := json.Marshal(params)
	if err != nil {
		return MaxRequestBytes + 1
	}
	return len(b)
}

// AllowedMethod is the UI↔core RPC allowlist (docs/contracts.md §2.2).
func AllowedMethod(method string) bool {
	switch method {
	case "ping", "health", "status", "start", "stop", "restart", "shutdown", "test", "diagnostics", "repair":
		return true
	default:
		return false
	}
}
