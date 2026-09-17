//go:build !windows && !darwin

package main

import "github.com/kardianos/service"

func elevateIfNeeded(string) error { return nil }

func prepareServiceInstall() error { return nil }

func afterInstall() {}

func afterUninstall() {}

func configureDemandStart() {}

func startService(svc service.Service) error { return svc.Start() }

func stopService(svc service.Service) error { return svc.Stop() }

func probeStatus() (string, bool) { return "", false }
