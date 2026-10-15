package dns

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestRestoreRetainsFailedServiceAndRetriesOriginalDNS(t *testing.T) {
	t.Setenv("OFFVEIL_DNS_RESTORE", filepath.Join(t.TempDir(), "restore.json"))
	ctl := &fakeSystemDNS{
		list: []hwService{{Name: "Wi-Fi", Device: "en0"}, {Name: "Ethernet", Device: "en1"}},
		dns:  map[string][]string{"Wi-Fi": {"192.0.2.53"}, "Ethernet": {"192.0.2.54"}},
	}
	if err := applySystemDNSWith(ctl, stubDNSIP); err != nil {
		t.Fatal(err)
	}
	ctl.setErr = map[string]error{"Wi-Fi": errors.New("temporary restore failure")}
	if _, err := restoreSystemDNSWith(ctl, true, false); err == nil {
		t.Fatal("expected restore failure")
	}
	snap, err := LoadRestoreSnapshot()
	if err != nil || snap == nil || len(snap.Services) != 1 || snap.Services[0].Name != "Wi-Fi" || snap.Services[0].DNS[0] != "192.0.2.53" {
		t.Fatalf("failed service must retain original DNS: %+v %v", snap, err)
	}
	if ctl.dns["Wi-Fi"][0] != stubDNSIP {
		t.Fatal("failed restore must not be replaced with DHCP")
	}
	if err := applySystemDNSWith(ctl, stubDNSIP); err == nil {
		t.Fatal("new session must not overwrite pending undo")
	}
	ctl.setErr = nil
	if _, err := restoreSystemDNSWith(ctl, true, false); err != nil {
		t.Fatal(err)
	}
	if got := ctl.dns["Wi-Fi"]; len(got) != 1 || got[0] != "192.0.2.53" {
		t.Fatalf("retry restored %v", got)
	}
	if snap, err := LoadRestoreSnapshot(); snap != nil || err != nil {
		t.Fatalf("completed restore: %+v %v", snap, err)
	}
}

func TestRestorePreservesOriginalLocalResolvers(t *testing.T) {
	for _, original := range []string{"127.0.0.1", "127.0.0.2", "::1"} {
		t.Run(original, func(t *testing.T) {
			t.Setenv("OFFVEIL_DNS_RESTORE", filepath.Join(t.TempDir(), "restore.json"))
			ctl := &fakeSystemDNS{list: []hwService{{Name: "Wi-Fi", Device: "en0"}}, dns: map[string][]string{"Wi-Fi": {original}}}
			if err := applySystemDNSWith(ctl, stubDNSIP); err != nil {
				t.Fatal(err)
			}
			if _, err := restoreSystemDNSWith(ctl, true, false); err != nil {
				t.Fatal(err)
			}
			got, dhcp, err := ctl.GetDNS("Wi-Fi")
			if err != nil || dhcp || len(got) != 1 || got[0] != original {
				t.Fatalf("original DNS lost: %v DHCP=%v %v", got, dhcp, err)
			}
		})
	}
}

func TestRestoreDoesNotFlushUnownedLocalResolver(t *testing.T) {
	t.Setenv("OFFVEIL_DNS_RESTORE", filepath.Join(t.TempDir(), "restore.json"))
	ctl := &fakeSystemDNS{list: []hwService{{Name: "Wi-Fi", Device: "en0"}}, dns: map[string][]string{"Wi-Fi": {"127.0.0.2"}}}
	if _, err := restoreSystemDNSWith(ctl, true, false); err != nil {
		t.Fatal(err)
	}
	if len(ctl.set) != 0 {
		t.Fatal("fallback changed another local resolver")
	}
	ctl.dns["Wi-Fi"] = []string{stubDNSIP}
	if _, err := restoreSystemDNSWith(ctl, false, false); err != nil {
		t.Fatal(err)
	}
	if len(ctl.set) != 0 {
		t.Fatal("unarmed restore changed DNS without an undo record")
	}
}

func TestApplyDoesNotGuessDNSAfterSnapshotReadFailure(t *testing.T) {
	t.Setenv("OFFVEIL_DNS_RESTORE", filepath.Join(t.TempDir(), "restore.json"))
	ctl := &fakeSystemDNS{list: []hwService{{Name: "Wi-Fi", Device: "en0"}}, getErr: map[string]error{"Wi-Fi": errors.New("unreadable DNS")}}
	if err := applySystemDNSWith(ctl, stubDNSIP); err == nil {
		t.Fatal("expected snapshot failure")
	}
	if len(ctl.set) != 0 {
		t.Fatal("DNS changed before original configuration was known")
	}
}
