package dns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestoreSnapshotRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dns-restore.json")
	t.Setenv("OFFVEIL_DNS_RESTORE", path)

	snap := RestoreSnapshot{
		StubIP: "127.0.0.1",
		Egress: &RestoreNIC{LUID: 42, DNS: []string{"192.168.1.1"}},
		Services: []ServiceDNS{
			{Name: "Wi-Fi", DNS: []string{"192.168.1.1"}},
			{Name: "Ethernet", DHCP: true},
		},
	}
	if err := SaveRestoreSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRestoreSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.StubIP != "127.0.0.1" || got.Egress == nil || got.Egress.LUID != 42 {
		t.Fatalf("got %+v", got)
	}
	if len(got.Egress.DNS) != 1 || got.Egress.DNS[0] != "192.168.1.1" {
		t.Fatalf("dns=%v", got.Egress.DNS)
	}
	if len(got.Services) != 2 || got.Services[0].Name != "Wi-Fi" || !got.Services[1].DHCP {
		t.Fatalf("services=%+v", got.Services)
	}
	if err := ClearRestoreSnapshot(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expected snapshot removed")
	}
	got, err = LoadRestoreSnapshot()
	if err != nil || got != nil {
		t.Fatalf("absent load got %+v err %v", got, err)
	}
}
