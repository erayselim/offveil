package engine

import (
	"strings"
)

const expandMaxHosts = 128

// ExpandInfo reports observed DNS demand. Network capture never needs guessed
// sibling hosts or additional per-host routes.
type ExpandInfo struct {
	HostsSeen   int `json:"hosts_seen"`
	RoutesAdded int `json:"routes_added"`
}

func normalizeExpandHost(host string) (string, bool) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") || strings.HasSuffix(host, ".arpa") || strings.HasSuffix(host, ".local") {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, char := range label {
			if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return "", false
			}
		}
	}
	return host, true
}

// System DNS must not wait for lifecycle operations or trigger per-query
// goroutines, network probes or speculative route changes.
func (e *Engine) observeDNSQuery(host string) {
	host, ok := normalizeExpandHost(host)
	if !ok || !e.mu.TryLock() {
		return
	}
	defer e.mu.Unlock()
	if !e.protection || len(e.expandSeen) >= expandMaxHosts {
		return
	}
	if e.expandSeen == nil {
		e.expandSeen = make(map[string]struct{})
	}
	e.expandSeen[host] = struct{}{}
}

func (e *Engine) expandInfoLocked() *ExpandInfo {
	if len(e.expandSeen) == 0 {
		return nil
	}
	return &ExpandInfo{HostsSeen: len(e.expandSeen)}
}

// HandleExpandQueryForTest records one actual query without network work.
func (e *Engine) HandleExpandQueryForTest(host string) { e.observeDNSQuery(host) }
