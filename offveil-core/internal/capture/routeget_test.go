package capture_test

import (
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
)

func TestIsVirtualDevice(t *testing.T) {
	for _, n := range []string{"utun0", "utun6", "ipsec0", "awdl0", "llw0", "bridge0", "lo0", "gif0"} {
		if !capture.IsVirtualDevice(n) {
			t.Fatalf("%s should be virtual", n)
		}
	}
	for _, n := range []string{"en0", "en1", "eth0", "wlan0"} {
		if capture.IsVirtualDevice(n) {
			t.Fatalf("%s should be physical", n)
		}
	}
}

func TestParseRouteGetDefault(t *testing.T) {
	out := `
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
`
	d := capture.ParseRouteGet(out)
	if d.Interface != "en0" || d.Gateway != "192.168.1.1" {
		t.Fatalf("%+v", d)
	}
}

func TestOursSplitDefault(t *testing.T) {
	if !capture.OursSplitDefault("utun6", "10.87.0.1") {
		t.Fatal("offveil TUN gateway")
	}
	if !capture.OursSplitDefault("utun6", "10.87.0.2") {
		t.Fatal("offveil TUN peer")
	}
	if capture.OursSplitDefault("utun6", "10.0.0.1") {
		t.Fatal("foreign VPN split-default must stay")
	}
	if capture.OursSplitDefault("en0", "192.168.1.1") {
		t.Fatal("physical default must stay")
	}
}

func TestPickEgressPreferSkipsUtun(t *testing.T) {
	adapters := []capture.AdapterInfo{
		{Name: "utun6", OperStatus: "up", Gateways: []string{"10.87.0.2"}, IsTUNLike: true, IPv4Metric: 1},
		{Name: "en0", OperStatus: "up", Gateways: []string{"192.168.1.1"}, UnicastAddrs: []string{"192.168.1.10"}, IPv4Metric: 20},
	}
	eg := capture.PickEgressPrefer(adapters, "utun6")
	if eg == nil || eg.Name != "en0" {
		t.Fatalf("want en0, got %+v", eg)
	}
	eg = capture.PickEgressPrefer(adapters, "en0")
	if eg == nil || eg.Name != "en0" || eg.IPv4 != "192.168.1.10" {
		t.Fatalf("want en0 ipv4, got %+v", eg)
	}
}
