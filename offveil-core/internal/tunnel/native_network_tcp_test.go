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
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/proc"
	"golang.org/x/net/proxy"
)

// SOCKS-only native fixtures never create TUN interfaces or change system DNS.
// Local exceptions are removed only to model a public opaque destination using
// owned loopback peers. A direct-route bug stays on the test's own echo server.
func TestNativeNetworkOpaqueTCPRouting(t *testing.T) {
	bin := os.Getenv("OFFVEIL_SINGBOX_TEST")
	if bin == "" {
		t.Skip("set OFFVEIL_SINGBOX_TEST to the pinned binary")
	}
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) {
			address := "127.0.0.1:0"
			if family == "tcp6" {
				address = "[::1]:0"
			}
			target, err := net.Listen(family, address)
			if err != nil {
				if family == "tcp6" {
					t.Skip(err)
				}
				t.Fatal(err)
			}
			defer target.Close()
			go func() {
				for {
					conn, err := target.Accept()
					if err != nil {
						return
					}
					go func() {
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
						_, _ = io.Copy(conn, conn)
					}()
				}
			}()
			upstream, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			seen := make(chan error, 1)
			go func() {
				conn, err := upstream.Accept()
				if err != nil {
					seen <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if err := fixtureSOCKSConnect(conn, target.Addr().String()); err != nil {
					seen <- err
					return
				}
				seen <- nil
				_, _ = io.Copy(conn, conn)
			}()
			reservation, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.Addr().(*net.TCPAddr).Port
			_ = reservation.Close()
			build, err := BuildSingBox(BuildParams{NetworkMode: true, EnableTUN: false, Provider: ProviderWARP, ListenPort: port, UpstreamSOCKS: upstream.Addr().String()})
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err = json.Unmarshal(build.JSON, &cfg); err != nil {
				t.Fatal(err)
			}
			route := cfg["route"].(map[string]any)
			var rules []any
			for _, raw := range route["rules"].([]any) {
				rule := raw.(map[string]any)
				if rule["outbound"] == "direct" {
					continue
				}
				rules = append(rules, rule)
			}
			route["rules"] = rules
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(t.TempDir(), "socks-only.json")
			if err = os.WriteFile(config, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "run", "-c", config)
			tail := &proc.TailBuffer{}
			cmd.Stderr = tail
			proc.PrepareCmd(cmd)
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			child := proc.WatchChild(cmd)
			defer child.Close()
			gateway := fmt.Sprintf("127.0.0.1:%d", port)
			if err = proc.WaitTCPContext(ctx, gateway, 5*time.Second, child); err != nil {
				t.Fatalf("gateway: %v %s", err, tail.String())
			}
			dialer, err := proxy.SOCKS5("tcp", gateway, nil, &net.Dialer{Timeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := dialer.Dial("tcp", target.Addr().String())
			if err != nil {
				t.Fatalf("opaque TCP: %v %s", err, tail.String())
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte{0x00, 0x04, 0xff, 0x7f, 0x01, 0x80, 0x00, 0x42}
			if _, err = conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err = io.ReadFull(conn, reply); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, reply) {
				t.Fatal("opaque payload changed")
			}
			select {
			case err = <-seen:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("opaque traffic bypassed the remote provider")
			}
		})
	}
}

func fixtureSOCKSConnect(conn net.Conn, want string) error {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:2]); err != nil {
		return err
	}
	if header[0] != 5 {
		return fmt.Errorf("invalid SOCKS version")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 1 {
		return fmt.Errorf("expected TCP CONNECT")
	}
	var address []byte
	switch header[3] {
	case 1:
		address = make([]byte, 4)
	case 4:
		address = make([]byte, 16)
	default:
		return fmt.Errorf("opaque IP unexpectedly depended on a domain")
	}
	if _, err := io.ReadFull(conn, address); err != nil {
		return err
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return err
	}
	got := net.JoinHostPort(net.IP(address).String(), fmt.Sprint(binary.BigEndian.Uint16(port[:])))
	if got != want {
		return fmt.Errorf("destination changed: %s != %s", got, want)
	}
	_, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	return err
}
