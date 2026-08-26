package capture_test

import (
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
)

func TestPickEgressPrefersLowerMetric(t *testing.T) {
	adapters := []capture.AdapterInfo{
		{Name: "Wi-Fi", OperStatus: "up", IPv4Metric: 40, Gateways: []string{"192.168.1.1"}},
		{Name: "Ethernet", OperStatus: "up", IPv4Metric: 25, Gateways: []string{"192.168.0.1"}},
		{Name: "offveil", OperStatus: "up", IPv4Metric: 5, Gateways: []string{"10.87.0.2"}, IsTUNLike: true},
		{Name: "Disconnected", OperStatus: "down", IPv4Metric: 1, Gateways: []string{"10.0.0.1"}},
	}
	eg := capture.PickEgress(adapters)
	if eg == nil || eg.Name != "Ethernet" {
		t.Fatalf("want Ethernet, got %+v", eg)
	}
}

func TestPickEgressCopiesIPv4(t *testing.T) {
	adapters := []capture.AdapterInfo{
		{
			Name: "Ethernet", OperStatus: "up", IPv4Metric: 25,
			Gateways:     []string{"192.168.0.1"},
			UnicastAddrs: []string{"fe80::1", "192.168.0.10"},
		},
	}
	eg := capture.PickEgress(adapters)
	if eg == nil || eg.IPv4 != "192.168.0.10" {
		t.Fatalf("want egress IPv4, got %+v", eg)
	}
}
