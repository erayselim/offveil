//go:build darwin

package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinNetsetupCtlUsesSystemBins(t *testing.T) {
	if networksetupBin != "/usr/sbin/networksetup" {
		t.Fatalf("networksetup=%s", networksetupBin)
	}
	if killallBin != "/usr/bin/killall" {
		t.Fatalf("killall=%s", killallBin)
	}
	if resolverOverlayDir != "/etc/resolver" {
		t.Fatalf("overlay=%s", resolverOverlayDir)
	}
}

func TestDarwinApplyRestoreWithInjectedRunner(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFVEIL_DNS_RESTORE", filepath.Join(dir, "dns-restore.json"))

	origNet := runNetsetup
	origKill := runKillallHUP
	t.Cleanup(func() {
		runNetsetup = origNet
		runKillallHUP = origKill
	})

	dns := map[string]string{
		"Wi-Fi": "192.168.1.1",
	}
	runNetsetup = func(args ...string) (string, error) {
		if usesResolverOverlay(args) {
			t.Fatal("/etc/resolver must not be used")
		}
		switch args[0] {
		case "-listnetworkserviceorder":
			return `An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) Tailscale
(Hardware Port: Tailscale, Device: utun4)
`, nil
		case "-getdnsservers":
			if args[1] == "Wi-Fi" {
				if v := dns["Wi-Fi"]; v == "" {
					return "There aren't any DNS Servers set on Wi-Fi.", nil
				} else {
					return v, nil
				}
			}
			return "There aren't any DNS Servers set on " + args[1] + ".", nil
		case "-setdnsservers":
			if args[1] == "Tailscale" {
				t.Fatal("must not set DNS on Tailscale/utun")
			}
			if args[2] == emptyDNSToken {
				dns[args[1]] = ""
			} else {
				dns[args[1]] = args[2]
			}
			return "", nil
		default:
			return "", nil
		}
	}
	flushed := 0
	runKillallHUP = func() error { flushed++; return nil }

	if err := applySystemDNSWith(liveSystemDNS(), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if dns["Wi-Fi"] != "127.0.0.1" {
		t.Fatalf("wifi=%s", dns["Wi-Fi"])
	}
	if flushed == 0 {
		t.Fatal("expected mDNSResponder HUP")
	}
	if _, err := os.Stat(filepath.Join(dir, "dns-restore.json")); err != nil {
		t.Fatal(err)
	}

	detail, err := RestoreLeftoverDNS(true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "restored") {
		t.Fatalf("detail=%s", detail)
	}
	if dns["Wi-Fi"] != "192.168.1.1" {
		t.Fatalf("restore wifi=%s", dns["Wi-Fi"])
	}
}
