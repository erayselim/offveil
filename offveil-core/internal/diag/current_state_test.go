package diag

import (
	"strings"
	"testing"
)

func TestSummaryDistinguishesUnavailableAndRetainedProtection(t *testing.T) {
	unknown := buildSummary(Input{Cascade: CascadeInfo{State: "unavailable"}, System: map[string]any{"protection_state": "unknown"}}, "fixture")
	if !strings.Contains(unknown, "protection=unknown") || strings.Contains(unknown, "protection=false") {
		t.Fatal(unknown)
	}
	retained := buildSummary(Input{Cascade: CascadeInfo{State: "active", Protection: true}, System: map[string]any{"protection_state": "off"}}, "fixture")
	if !strings.Contains(retained, "protection=off") || !strings.Contains(retained, "retained active session") {
		t.Fatal(retained)
	}
}
