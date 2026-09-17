package appservice

import (
	"strings"
	"testing"
)

func TestDarwinLaunchdOptionsDemandStart(t *testing.T) {
	opt := DarwinLaunchdOptions()
	if v, _ := opt["KeepAlive"].(bool); v {
		t.Fatal("KeepAlive must be false (kardianos default true breaks Stop)")
	}
	if v, _ := opt["RunAtLoad"].(bool); v {
		t.Fatal("RunAtLoad must be false (boot must not start the daemon)")
	}
	if v, _ := opt["UserService"].(bool); v {
		t.Fatal("UserService must be false (LaunchDaemon, not LaunchAgent)")
	}
}

func TestSudoersBodyStartStopOnly(t *testing.T) {
	exe := `/Library/Application Support/offveil/offveil-core`
	body := SudoersBody(exe)
	if !strings.Contains(body, `Application\ Support`) {
		t.Fatalf("sudoers must escape spaces:\n%s", body)
	}
	if !strings.Contains(body, "NOPASSWD") {
		t.Fatal("expected NOPASSWD")
	}
	if !strings.Contains(body, "offveil-core start") {
		t.Fatalf("expected start command:\n%s", body)
	}
	if !strings.Contains(body, "offveil-core stop") {
		t.Fatalf("expected stop command:\n%s", body)
	}
	aliasLine := ""
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "Cmnd_Alias OFFVEIL_CTL") {
			aliasLine = line
		}
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, forbid := range []string{" setup", " install", " uninstall", " repair", " run"} {
			if strings.Contains(line, "offveil-core"+forbid) {
				t.Fatalf("sudoers must not allow %q:\n%s", forbid, body)
			}
		}
	}
	if aliasLine == "" {
		t.Fatalf("missing Cmnd_Alias:\n%s", body)
	}
	if strings.Contains(body, "Network Extension") {
		t.Fatal("sudoers must not mention Network Extension")
	}
}

func TestElevateScriptAdminShell(t *testing.T) {
	s := ElevateScript(`/Library/Application Support/offveil/offveil-core`, "eray", "setup")
	if !strings.Contains(s, "with administrator privileges") {
		t.Fatalf("missing admin privileges: %s", s)
	}
	if !strings.Contains(s, "OFFVEIL_SETUP_USER=") {
		t.Fatalf("missing setup user: %s", s)
	}
	if !strings.Contains(s, "setup") {
		t.Fatalf("missing action: %s", s)
	}
}

func TestCanonicalBinaryAndPlist(t *testing.T) {
	if !strings.Contains(CanonicalBinary(), "offveil-core") {
		t.Fatalf("CanonicalBinary=%q", CanonicalBinary())
	}
	if LaunchDaemonPlist != "/Library/LaunchDaemons/offveil-core.plist" {
		t.Fatalf("plist=%s", LaunchDaemonPlist)
	}
	if SudoersPath != "/etc/sudoers.d/offveil" {
		t.Fatalf("sudoers=%s", SudoersPath)
	}
	if NeedsInstallPrefix != "needs_install:" {
		t.Fatalf("prefix=%s", NeedsInstallPrefix)
	}
}
