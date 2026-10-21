package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/proc"
)

// This complements the packet-level test module: the pinned native binary
// exercises real UDP sockets, physical-interface binding and routing rules.
// Its TUN inbound is removed; it cannot change host routes or DNS.
func TestNativeOpaqueUDPDirectRoundTrip(t *testing.T) {
	bin := os.Getenv("OFFVEIL_SINGBOX_TEST")
	if bin == "" {
		t.Skip("set OFFVEIL_SINGBOX_TEST to the pinned sing-box binary")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	loopback := ""
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			loopback = iface.Name
			break
		}
	}
	if loopback == "" {
		t.Fatal("no loopback interface")
	}
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		var packet [65535]byte
		for {
			n, peer, err := echo.ReadFromUDP(packet[:])
			if err != nil {
				return
			}
			if _, err := echo.WriteToUDP(packet[:n], peer); err != nil {
				return
			}
		}
	}()
	defer func() { _ = echo.Close(); <-done }()
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	_ = reservation.Close()
	build, err := BuildSingBox(BuildParams{NetworkMode: true, Provider: ProviderDesync, EnableTUN: false, ListenPort: port,
		EgressInterface: loopback, DesyncSOCKSPort: 1})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(build.JSON, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["inbounds"] = cfg["inbounds"].([]any)[:1]
	cfg["log"].(map[string]any)["level"] = "debug"
	route := cfg["route"].(map[string]any)
	route["auto_detect_interface"] = false
	var rules []any
	for _, raw := range route["rules"].([]any) {
		// Substitute an owned loopback endpoint for an unrelated public peer.
		// The packet must exercise the generic UDP rule, not the private rule.
		rule := raw.(map[string]any)
		if rule["ip_is_private"] != true && !(rule["ip_cidr"] != nil && rule["outbound"] == "direct") {
			rules = append(rules, raw)
		}
	}
	route["rules"] = rules
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", path)
	tail := &proc.TailBuffer{}
	cmd.Stderr = tail
	proc.PrepareCmd(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child := proc.WatchChild(cmd)
	defer child.Close()
	proxy := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	if err := proc.WaitTCP(proxy, 3*time.Second, child); err != nil {
		t.Fatalf("%v: %s", err, tail.String())
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{64, 1200, 1252, 1253, 1300, 4096} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			helper := exec.CommandContext(ctx, self, "-test.run=^TestNativeUDPClient$")
			helper.Env = append(os.Environ(), "OFFVEIL_UDP_TEST_PROXY="+proxy,
				"OFFVEIL_UDP_TEST_PORT="+strconv.Itoa(echo.LocalAddr().(*net.UDPAddr).Port), "OFFVEIL_UDP_TEST_BYTES="+strconv.Itoa(size))
			if out, err := helper.CombinedOutput(); err != nil {
				t.Fatalf("UDP round trip: %v\n%s\n%s", err, out, tail.String())
			}
		})
	}
}
