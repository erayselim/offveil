//go:build darwin

package support

import (
	"context"
	"os/exec"
	"strings"
	"time"

	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
)

func platformFacts(ctx context.Context, facts map[string]any) {
	query, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if version, err := exec.CommandContext(query, "/usr/bin/sw_vers", "-productVersion").Output(); err == nil {
		facts["macos_version"] = strings.TrimSpace(string(version))
	}
	facts["private_relay_hints"] = offdns.RelayDiagNotes()
}
