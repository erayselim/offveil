//go:build windows

package main

import (
	"log/slog"
	"os/exec"

	"github.com/kardianos/service"

	"github.com/erayselim/offveil/offveil-core/internal/appservice"
)

func elevateIfNeeded(string) error { return nil }

func prepareServiceInstall() error { return nil }

func afterInstall() {}

func afterUninstall() {}

func startService(svc service.Service) error { return svc.Start() }

func stopService(svc service.Service) error { return svc.Stop() }

func configureDemandStart() {
	configureManualStart()
	configureStartDACL()
}

func configureManualStart() {
	out, err := runSC("config", appservice.Name, "start=", "demand")
	if err != nil {
		slog.Warn("setup: could not set StartType=manual", "err", err, "out", out)
		return
	}
	slog.Info("setup: StartType=manual (UI lifecycle)")
}

// Authenticated Users may StartService without UAC so login auto-connect works.
func configureStartDACL() {
	sddl := "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;AU)"
	out, err := runSC("sdset", appservice.Name, sddl)
	if err != nil {
		slog.Warn("setup: could not set service DACL", "err", err, "out", out)
		return
	}
	slog.Info("setup: AU SERVICE_START granted")
}

func runSC(args ...string) (string, error) {
	cmd := exec.Command("sc.exe", args...)
	b, err := cmd.CombinedOutput()
	return string(b), err
}

func probeStatus() (string, bool) { return "", false }
