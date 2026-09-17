package dns

import (
	"strings"
	"testing"
)

func TestParseListAllNetworkServices(t *testing.T) {
	out := `An asterisk (*) denotes that a network service is disabled.
Wi-Fi
Ethernet
*Bluetooth PAN
Thunderbolt Bridge
Tailscale
Thunderbolt Ethernet
`
	got := parseListAllNetworkServices(out)
	if len(got) != 6 {
		t.Fatalf("len=%d %+v", len(got), got)
	}
	if got[0].Name != "Wi-Fi" || got[0].Disabled {
		t.Fatalf("wifi=%+v", got[0])
	}
	if !got[2].Disabled || got[2].Name != "Bluetooth PAN" {
		t.Fatalf("bt=%+v", got[2])
	}
}

func TestParseListNetworkServiceOrder(t *testing.T) {
	out := `An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) Thunderbolt Ethernet
(Hardware Port: Thunderbolt Ethernet, Device: en1)

*(3) Bluetooth PAN
(Hardware Port: Bluetooth PAN, Device: en2)

(4) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(5) Tailscale
(Hardware Port: Tailscale, Device: utun4)

(6) Ethernet
(Hardware Port: Ethernet, Device: en7)
`
	got := parseListNetworkServiceOrder(out)
	if len(got) != 6 {
		t.Fatalf("len=%d %+v", len(got), got)
	}
	if got[0].Device != "en0" || got[0].Name != "Wi-Fi" {
		t.Fatalf("wifi=%+v", got[0])
	}
	if !got[2].Disabled {
		t.Fatalf("bt should be disabled: %+v", got[2])
	}
	if got[4].Device != "utun4" {
		t.Fatalf("tailscale=%+v", got[4])
	}
}

func TestFilterDNSTargetsSkipsVPNUtunBridge(t *testing.T) {
	in := []hwService{
		{Name: "Wi-Fi", HardwarePort: "Wi-Fi", Device: "en0"},
		{Name: "Ethernet", HardwarePort: "Ethernet", Device: "en1"},
		{Name: "Thunderbolt Ethernet", HardwarePort: "Thunderbolt Ethernet", Device: "en8"},
		{Name: "Thunderbolt Bridge", HardwarePort: "Thunderbolt Bridge", Device: "bridge0"},
		{Name: "Tailscale", HardwarePort: "Tailscale", Device: "utun4"},
		{Name: "Cisco AnyConnect", HardwarePort: "VPN", Device: "utun2"},
		{Name: "Bluetooth PAN", HardwarePort: "Bluetooth PAN", Device: "en3"},
		{Name: "iPhone USB", HardwarePort: "iPhone USB", Device: "en4"},
		{Name: "off", Disabled: true, Device: "en9"},
	}
	got := filterDNSTargets(in)
	var names []string
	for _, s := range got {
		names = append(names, s.Name)
	}
	want := []string{"Wi-Fi", "Ethernet", "Thunderbolt Ethernet", "iPhone USB"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", names, want)
	}
}

func TestParseGetDNSServers(t *testing.T) {
	servers, dhcp := parseGetDNSServers("There aren't any DNS Servers set on Wi-Fi.")
	if !dhcp || len(servers) != 0 {
		t.Fatalf("dhcp servers=%v dhcp=%v", servers, dhcp)
	}
	servers, dhcp = parseGetDNSServers("8.8.8.8\n1.1.1.1\n")
	if dhcp || len(servers) != 2 || servers[0] != "8.8.8.8" {
		t.Fatalf("got %v dhcp=%v", servers, dhcp)
	}
	servers, dhcp = parseGetDNSServers("127.0.0.1")
	if dhcp || !onlyLoopbackStub(servers) {
		t.Fatalf("stub %v dhcp=%v", servers, dhcp)
	}
}

func TestSetDNSArgsEmptyAndStub(t *testing.T) {
	empty := setDNSArgs("Wi-Fi", nil)
	if empty[len(empty)-1] != emptyDNSToken {
		t.Fatalf("empty args=%v", empty)
	}
	stub := setDNSArgs("Wi-Fi", []string{"127.0.0.1"})
	if strings.Join(stub, " ") != "-setdnsservers Wi-Fi 127.0.0.1" {
		t.Fatalf("stub args=%v", stub)
	}
	if usesResolverOverlay(empty) || usesResolverOverlay(stub) || usesResolverOverlay(listAllArgs()) {
		t.Fatal("must not touch /etc/resolver")
	}
	flush := flushResolverArgs()
	if strings.Join(flush, " ") != "-HUP mDNSResponder" {
		t.Fatalf("flush=%v", flush)
	}
}

func TestApplyAndRestoreSystemDNS(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFVEIL_DNS_RESTORE", dir+"/dns-restore.json")

	ctl := &fakeSystemDNS{
		list: []hwService{
			{Name: "Wi-Fi", Device: "en0"},
			{Name: "Tailscale", Device: "utun4"},
			{Name: "Ethernet", Device: "en1"},
		},
		dns: map[string][]string{
			"Wi-Fi":    {"192.168.1.1"},
			"Ethernet": nil, // DHCP
		},
	}
	if err := applySystemDNSWith(ctl, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if ctl.set["Wi-Fi"][0] != "127.0.0.1" || ctl.set["Ethernet"][0] != "127.0.0.1" {
		t.Fatalf("set=%v", ctl.set)
	}
	if _, ok := ctl.set["Tailscale"]; ok {
		t.Fatal("must not set DNS on utun/VPN")
	}
	if ctl.flushCount == 0 {
		t.Fatal("expected flush after apply")
	}
	snap, err := LoadRestoreSnapshot()
	if err != nil || snap == nil || len(snap.Services) != 2 {
		t.Fatalf("snap=%+v err=%v", snap, err)
	}

	detail, err := restoreSystemDNSWith(ctl, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "restored") {
		t.Fatalf("detail=%s", detail)
	}
	if got := ctl.set["Wi-Fi"]; len(got) != 1 || got[0] != "192.168.1.1" {
		t.Fatalf("wifi restore=%v", got)
	}
	if got := ctl.set["Ethernet"]; got != nil && len(got) != 0 {
		t.Fatalf("ethernet should be empty/DHCP, got %v", got)
	}
	got, err := LoadRestoreSnapshot()
	if err != nil || got != nil {
		t.Fatalf("snapshot should be cleared: %+v %v", got, err)
	}
}

func TestRestoreFlushesLeftoverStubWithoutSnapshot(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFVEIL_DNS_RESTORE", dir+"/dns-restore.json")

	ctl := &fakeSystemDNS{
		list: []hwService{{Name: "Wi-Fi", Device: "en0"}},
		dns:  map[string][]string{"Wi-Fi": {"127.0.0.1"}},
	}
	detail, err := restoreSystemDNSWith(ctl, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "flushed") {
		t.Fatalf("detail=%s", detail)
	}
	if got := ctl.set["Wi-Fi"]; got != nil && len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}

func TestApplyDoesNotUseResolverOverlay(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFVEIL_DNS_RESTORE", dir+"/dns-restore.json")
	ctl := &fakeSystemDNS{
		list: []hwService{{Name: "Wi-Fi", Device: "en0"}},
		dns:  map[string][]string{},
	}
	if err := applySystemDNSWith(ctl, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, a := range ctl.calls {
		if usesResolverOverlay(a) {
			t.Fatalf("resolver overlay in %v", a)
		}
	}
}

func TestApplyNoHardwareServices(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFVEIL_DNS_RESTORE", dir+"/dns-restore.json")
	ctl := &fakeSystemDNS{
		list: []hwService{{Name: "Tailscale", Device: "utun4"}},
	}
	if err := applySystemDNSWith(ctl, "127.0.0.1"); err == nil {
		t.Fatal("expected error when only VPN/utun services exist")
	}
}

func TestLeftoverStubPresent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFVEIL_DNS_RESTORE", dir+"/dns-restore.json")
	ctl := &fakeSystemDNS{
		list: []hwService{{Name: "Wi-Fi", Device: "en0"}},
		dns:  map[string][]string{"Wi-Fi": {"8.8.8.8"}},
	}
	if leftoverStubPresent(ctl) {
		t.Fatal("clean should be false")
	}
	ctl.dns["Wi-Fi"] = []string{"127.0.0.1"}
	if !leftoverStubPresent(ctl) {
		t.Fatal("stub leftover should be true")
	}
}

type fakeSystemDNS struct {
	list       []hwService
	dns        map[string][]string // nil value => DHCP
	set        map[string][]string
	calls      [][]string
	flushCount int
	setErr     map[string]error
}

func (f *fakeSystemDNS) ListServices() ([]hwService, error) {
	return append([]hwService{}, f.list...), nil
}

func (f *fakeSystemDNS) GetDNS(name string) ([]string, bool, error) {
	v, ok := f.dns[name]
	if !ok || v == nil {
		return nil, true, nil
	}
	return append([]string{}, v...), false, nil
}

func (f *fakeSystemDNS) SetDNS(name string, servers []string) error {
	if f.set == nil {
		f.set = map[string][]string{}
	}
	f.calls = append(f.calls, setDNSArgs(name, servers))
	if f.setErr != nil {
		if err, ok := f.setErr[name]; ok {
			return err
		}
	}
	if servers == nil {
		f.set[name] = []string{}
		f.dns[name] = nil
		return nil
	}
	cp := append([]string{}, servers...)
	f.set[name] = cp
	f.dns[name] = cp
	return nil
}

func (f *fakeSystemDNS) Flush() error {
	f.flushCount++
	f.calls = append(f.calls, flushResolverArgs())
	return nil
}
