//go:build darwin

package capture

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

var splitDefaultDests = []string{"0.0.0.0/1", "128.0.0.0/1"}

var runRoute = func(args ...string) (string, error) {
	cmd := exec.Command("/sbin/route", args...)
	b, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

// AdapterPresent is true when a leftover split-default route still points
// at offveil's TUN address. utun itself cannot be closed without the FD.
func AdapterPresent() bool {
	for _, dest := range splitDefaultDests {
		out, err := runRoute("-n", "get", dest)
		if err != nil {
			continue
		}
		d := ParseRouteGet(out)
		if OursSplitDefault(d.Interface, d.Gateway) {
			return true
		}
	}
	return false
}

// CloseOrphanAdapter is Windows Wintun-only. Darwin cannot destroy a utun
// without the owning FD; leftover split-default routes are ClearLeftoverRoutes.
func CloseOrphanAdapter() error { return nil }

// ClearLeftoverRoutes deletes 0.0.0.0/1 and 128.0.0.0/1 only when they still
// point at 10.87.0.1/30. Other VPNs' split-defaults are left alone.
func ClearLeftoverRoutes() (string, error) {
	var removed []string
	var first error
	for _, dest := range splitDefaultDests {
		out, err := runRoute("-n", "get", dest)
		if err != nil {
			continue
		}
		low := strings.ToLower(out)
		if strings.Contains(low, "not in table") {
			continue
		}
		d := ParseRouteGet(out)
		if !OursSplitDefault(d.Interface, d.Gateway) {
			continue
		}
		if _, err := runRoute("-n", "delete", "-net", dest); err != nil {
			if first == nil {
				first = fmt.Errorf("%s: %w", dest, err)
			}
			slog.Warn("capture: leftover route delete", "dest", dest, "err", err)
			continue
		}
		removed = append(removed, dest)
	}
	if len(removed) == 0 {
		if first != nil {
			return "", first
		}
		return "absent", nil
	}
	slog.Info("capture: leftover split-default removed", "dest", removed)
	return "removed " + strings.Join(removed, ","), first
}
