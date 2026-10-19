package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/proc"
)

var stunProbe = []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

func socksUDPAddress(conn net.Conn) (*net.UDPAddr, error) {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var auth [2]byte
	if _, err := io.ReadFull(conn, auth[:]); err != nil {
		return nil, err
	}
	if auth != [2]byte{5, 0} {
		return nil, fmt.Errorf("SOCKS auth=%v", auth)
	}
	if _, err := conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, err
	}
	if reply[1] != 0 || reply[3] != 1 {
		return nil, fmt.Errorf("SOCKS UDP reply=%v", reply)
	}
	var addr [6]byte
	if _, err := io.ReadFull(conn, addr[:]); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: net.IP(addr[:4]), Port: int(binary.BigEndian.Uint16(addr[4:]))}, nil
}

func TestNativeUDPClient(t *testing.T) {
	proxy := os.Getenv("OFFVEIL_UDP_TEST_PROXY")
	if proxy == "" {
		return
	}
	// SOCKS metadata uses the control connection's source port; TUN uses the UDP
	// source. Let Windows choose a valid TCP source first: a UDP auto-port can
	// fall inside a TCP exclusion range and make every explicit TCP bind fail.
	var conn net.Conn
	var udp *net.UDPConn
	var err error
	for range 32 {
		conn, err = net.DialTimeout("tcp4", proxy, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: conn.LocalAddr().(*net.TCPAddr).Port})
		if err == nil {
			break
		}
		_ = conn.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer udp.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	address, err := socksUDPAddress(conn)
	if err != nil {
		t.Fatal(err)
	}
	_ = udp.SetDeadline(time.Now().Add(4 * time.Second))
	payload := stunProbe
	if size, err := strconv.Atoi(os.Getenv("OFFVEIL_UDP_TEST_BYTES")); err == nil && size >= len(stunProbe) && size <= 60000 {
		payload = append(bytes.Repeat([]byte{0xa5}, size-len(stunProbe)), stunProbe...)
	}
	packet := append([]byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 9}, payload...)
	if port, err := strconv.Atoi(os.Getenv("OFFVEIL_UDP_TEST_PORT")); err == nil {
		binary.BigEndian.PutUint16(packet[8:10], uint16(port))
	}
	if _, err := udp.WriteToUDP(packet, address); err != nil {
		t.Fatal(err)
	}
	var response [65535]byte
	n, _, err := udp.ReadFromUDP(response[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(response[:n], payload) {
		t.Fatalf("unexpected response: %x", response[:n])
	}
}

// Exercise sing-box's real process lookup and raw UDP routing; no TUN or public traffic.
func TestNativeApplicationUDPRouting(t *testing.T) {
	bin := os.Getenv("OFFVEIL_SINGBOX_TEST")
	if bin == "" {
		t.Skip("set OFFVEIL_SINGBOX_TEST to the pinned sing-box binary")
	}
	socks, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	seen := make(chan error, 1)
	go func() {
		var packet [512]byte
		_ = relay.SetDeadline(time.Now().Add(8 * time.Second))
		n, peer, err := relay.ReadFromUDP(packet[:])
		if err == nil && !bytes.HasSuffix(packet[:n], stunProbe) {
			err = fmt.Errorf("unexpected proxy payload")
		}
		if err == nil {
			_, err = relay.WriteToUDP(packet[:n], peer)
		}
		seen <- err
	}()
	go func() {
		conn, err := socks.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		var greeting [3]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil {
			return
		}
		_, _ = conn.Write([]byte{5, 0})
		var request [10]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil {
			return
		}
		if request[1] != 3 {
			return
		}
		reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
		binary.BigEndian.PutUint16(reply[8:], uint16(relay.LocalAddr().(*net.UDPAddr).Port))
		_, _ = conn.Write(reply)
		_, _ = io.Copy(io.Discard, conn)
	}()
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	_ = reservation.Close()
	build, err := BuildSingBox(BuildParams{Provider: ProviderDesync, EnableTUN: true, ListenPort: port,
		SpecialDomains: []string{"discord.com"}, DesyncSOCKSHost: "127.0.0.1", DesyncSOCKSPort: socks.Addr().(*net.TCPAddr).Port})
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
	route["auto_detect_interface"] = false // This test substitutes loopback for public destinations.
	var rules []any
	for _, raw := range route["rules"].([]any) {
		if raw.(map[string]any)["ip_is_private"] != true {
			rules = append(rules, raw)
		}
	}
	route["rules"] = rules
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sing-box.json")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", configPath)
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
	clientPath := filepath.Join(dir, "Discord")
	if runtime.GOOS == "windows" {
		clientPath += ".exe"
	}
	client, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientPath, client, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	helper := exec.CommandContext(ctx, clientPath, "-test.run=^TestNativeUDPClient$")
	helper.Env = append(os.Environ(), "OFFVEIL_UDP_TEST_PROXY="+proxy)
	if out, err := helper.CombinedOutput(); err != nil {
		t.Fatalf("UDP client: %v\n%s\n%s", err, out, tail.String())
	}
	if err := <-seen; err != nil {
		t.Fatal(err)
	}
	// An unrelated game's UDP must reach its destination without visiting ByeDPI.
	direct, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	go func() {
		var packet [512]byte
		_ = direct.SetDeadline(time.Now().Add(5 * time.Second))
		n, peer, err := direct.ReadFromUDP(packet[:])
		if err == nil {
			_, _ = direct.WriteToUDP(packet[:n], peer)
		}
	}()
	gamePath := filepath.Join(dir, "RobloxPlayer")
	if runtime.GOOS == "windows" {
		gamePath += ".exe"
	}
	if err := os.WriteFile(gamePath, client, 0o700); err != nil {
		t.Fatal(err)
	}
	game := exec.CommandContext(ctx, gamePath, "-test.run=^TestNativeUDPClient$")
	game.Env = append(os.Environ(), "OFFVEIL_UDP_TEST_PROXY="+proxy, "OFFVEIL_UDP_TEST_PORT="+strconv.Itoa(direct.LocalAddr().(*net.UDPAddr).Port))
	if out, err := game.CombinedOutput(); err != nil {
		t.Fatalf("game UDP: %v\n%s\n%s", err, out, tail.String())
	}
}
