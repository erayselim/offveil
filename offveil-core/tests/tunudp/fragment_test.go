//go:build with_gvisor

package tunudp_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	offveil "github.com/erayselim/offveil/offveil-core/internal/tunnel"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// This is a packet-level TUN, not a SOCKS substitute. Synthetic public IP
// packets enter the same pinned stacks as the bundled sing-box. No adapter,
// system route, DNS setting, firewall rule or public endpoint is used.
type memoryTUN struct {
	ctx     context.Context
	in, out chan []byte
	closed  chan struct{}
	once    sync.Once
	mtu     uint32
}

func (t *memoryTUN) Name() (string, error)                { return "offveil-packet-test", nil }
func (t *memoryTUN) Start() error                         { return nil }
func (t *memoryTUN) UpdateRouteOptions(tun.Options) error { return nil }
func (t *memoryTUN) Close() error                         { t.once.Do(func() { close(t.closed) }); return nil }
func (t *memoryTUN) ReadPacket() ([]byte, func(), error) {
	select {
	case p := <-t.in:
		return p, func() {}, nil
	case <-t.closed:
		return nil, nil, os.ErrClosed
	case <-t.ctx.Done():
		return nil, nil, t.ctx.Err()
	}
}
func (t *memoryTUN) Read(p []byte) (int, error) {
	b, release, err := t.ReadPacket()
	if err != nil {
		return 0, err
	}
	defer release()
	return copy(p, b), nil
}
func (t *memoryTUN) Write(p []byte) (int, error) {
	// System-stack writes include Darwin's address-family prefix. The memory
	// device exposes raw IP packets like Wintun; gVisor WritePacket is already
	// raw IP on every platform and must not lose its network header.
	written := len(p)
	if tun.PacketOffset > 0 && len(p) > tun.PacketOffset && p[0]>>4 != 4 && p[0]>>4 != 6 {
		version := p[tun.PacketOffset] >> 4
		if version == 4 || version == 6 {
			p = p[tun.PacketOffset:]
		}
	}
	select {
	case t.out <- bytes.Clone(p):
		return written, nil
	case <-t.closed:
		return 0, os.ErrClosed
	case <-t.ctx.Done():
		return 0, t.ctx.Err()
	}
}
func (t *memoryTUN) WritePacket(p *stack.PacketBuffer) (int, error) {
	v := p.ToView()
	defer v.Release()
	return t.Write(v.AsSlice())
}
func (t *memoryTUN) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	ep := channel.New(64, t.mtu, "")
	go func() {
		for {
			p, release, err := t.ReadPacket()
			if err != nil {
				return
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
			ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
			pkt.DecRef()
			release()
		}
	}()
	go func() {
		for {
			p := ep.ReadContext(t.ctx)
			if p == nil {
				return
			}
			_, _ = t.WritePacket(p)
			p.DecRef()
		}
	}()
	return ep, stack.NICOptions{}, nil
}

type datagram struct {
	payload             []byte
	source, destination M.Socksaddr
}
type packetHandler struct {
	received chan datagram
	errors   chan error
}

func (h *packetHandler) PrepareConnection(string, M.Socksaddr, M.Socksaddr, tun.DirectRouteContext, time.Duration) (tun.DirectRouteDestination, error) {
	return nil, nil
}
func (h *packetHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(io.EOF)
	}
}
func (h *packetHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		p := buf.NewSize(65535)
		dst, err := conn.ReadPacket(p)
		if err != nil {
			p.Release()
			return
		}
		payload := bytes.Clone(p.Bytes())
		p.Release()
		select {
		case h.received <- datagram{payload, source, dst}:
		case <-ctx.Done():
			return
		}
		reply := buf.NewSize(len(payload))
		_, _ = reply.Write(payload)
		if err := conn.WritePacket(reply, dst); err != nil {
			select {
			case h.errors <- err:
			default:
			}
			return
		}
	}
}

func startPacketStack(t *testing.T, name string, mtu int) (*memoryTUN, *packetHandler) {
	t.Helper()
	assertNoFirewallSideEffects(t)
	ctx, cancel := context.WithCancel(context.Background())
	device := &memoryTUN{ctx: ctx, in: make(chan []byte, 32), out: make(chan []byte, 32), closed: make(chan struct{}), mtu: uint32(mtu)}
	handler := &packetHandler{received: make(chan datagram, 16), errors: make(chan error, 4)}
	s, err := tun.NewStack(name, tun.StackOptions{
		Context: ctx, Tun: device,
		// Only the system TCP forwarder's disposable listener uses loopback.
		// UDP packets retain the production TUN source and synthetic public peer.
		TunOptions: tun.Options{Inet4Address: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/30")}, MTU: uint32(mtu)},
		UDPTimeout: time.Second, ICMPTimeout: time.Second, Handler: handler, Logger: logger.NOP(),
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		cancel()
		_ = device.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = device.Close(); _ = s.Close() })
	return device, handler
}

func ipChecksum(p []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(p); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	if len(p)%2 != 0 {
		sum += uint32(p[len(p)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpFragments(payload []byte, mtu int, id uint16) [][]byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], 45001)
	binary.BigEndian.PutUint16(udp[2:4], 33445)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload) // A zero UDP checksum is valid for IPv4.
	var packets [][]byte
	maxPart := ((mtu - 20) / 8) * 8
	for offset := 0; offset < len(udp); {
		end := len(udp)
		if end-offset > mtu-20 {
			end = offset + maxPart
		}
		p := make([]byte, 20+end-offset)
		p[0], p[8], p[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		binary.BigEndian.PutUint16(p[4:6], id)
		fragment := uint16(offset / 8)
		if end < len(udp) {
			fragment |= 0x2000
		}
		binary.BigEndian.PutUint16(p[6:8], fragment)
		copy(p[12:16], []byte{10, 87, 0, 1})
		copy(p[16:20], []byte{198, 51, 100, 7})
		binary.BigEndian.PutUint16(p[10:12], ipChecksum(p[:20]))
		copy(p[20:], udp[offset:end])
		packets = append(packets, p)
		offset = end
	}
	return packets
}

func awaitDatagram(t *testing.T, h *packetHandler, want []byte) {
	t.Helper()
	select {
	case p := <-h.received:
		if !bytes.Equal(p.payload, want) || p.source.Addr.String() != "10.87.0.1" || p.source.Port != 45001 || p.destination.Addr.String() != "198.51.100.7" || p.destination.Port != 33445 {
			t.Fatalf("datagram payload or endpoints corrupted: bytes=%d source=%s peer=%s", len(p.payload), p.source, p.destination)
		}
	case err := <-h.errors:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatalf("%d-byte UDP datagram never reached the forwarding handler", len(want))
	}
}

func awaitReply(t *testing.T, device *memoryTUN, want []byte) {
	t.Helper()
	got := make([]byte, 8+len(want))
	covered := make([]bool, len(got))
	count := 0
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for count < len(got) {
		select {
		case p := <-device.out:
			if len(p) < 20 || p[9] != 17 || ipChecksum(p[:20]) != 0 {
				t.Fatal("invalid IPv4 UDP reply")
			}
			if !bytes.Equal(p[12:16], []byte{198, 51, 100, 7}) || !bytes.Equal(p[16:20], []byte{10, 87, 0, 1}) {
				t.Fatal("reply addresses changed")
			}
			offset := int(binary.BigEndian.Uint16(p[6:8])&0x1fff) * 8
			part := p[int(p[0]&15)*4:]
			if offset+len(part) > len(got) {
				t.Fatal("reply exceeds original datagram size")
			}
			copy(got[offset:], part)
			for i := offset; i < offset+len(part); i++ {
				if !covered[i] {
					covered[i] = true
					count++
				}
			}
		case <-timer.C:
			t.Fatal("UDP reply was truncated, lost or not reassembled")
		}
	}
	if !bytes.Equal(got[8:], want) || binary.BigEndian.Uint16(got[:2]) != 33445 || binary.BigEndian.Uint16(got[2:4]) != 45001 {
		t.Fatal("UDP reply payload/ports changed")
	}
}

func TestPinnedSystemDropsFragmentedDatagrams(t *testing.T) {
	device, handler := startPacketStack(t, "system", 1280)
	control := bytes.Repeat([]byte{0x5a}, 64)
	device.in <- udpFragments(control, 1280, 1)[0]
	awaitDatagram(t, handler, control)
	awaitReply(t, device, control)
	for _, p := range udpFragments(bytes.Repeat([]byte{0xa5}, 1300), 1280, 2) {
		device.in <- p
	}
	select {
	case p := <-handler.received:
		t.Fatalf("pinned legacy system behavior changed: received %d bytes", len(p.payload))
	case <-time.After(200 * time.Millisecond):
		t.Log("legacy system: 64-byte control passes; fragmented 1300-byte UDP is dropped")
	}
}

func TestConfiguredStackPreservesOpaqueUDPDatagrams(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("configured capture stacks are shipped on Windows and macOS")
	}
	build, err := offveil.BuildSingBox(offveil.BuildParams{Provider: offveil.ProviderDesync, EnableTUN: true})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []struct {
			Type  string `json:"type"`
			Stack string `json:"stack"`
			MTU   int    `json:"mtu"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(build.JSON, &cfg); err != nil {
		t.Fatal(err)
	}
	var name string
	var mtu int
	for _, in := range cfg.Inbounds {
		if in.Type == "tun" {
			name, mtu = in.Stack, in.MTU
		}
	}
	checkUDPDatagrams(t, name, mtu)
}

// Exercise the full gVisor fixture on Windows as well, before macOS CI uses it.
func TestGVisorReferencePreservesOpaqueUDPDatagrams(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("already exercised through the configured stack")
	}
	checkUDPDatagrams(t, "gvisor", 1280)
}

func checkUDPDatagrams(t *testing.T, name string, mtu int) {
	t.Helper()
	for _, size := range []int{64, 1200, 1252, 1253, 1300, 4096} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%d/reverse=%v", name, size, reverse), func(t *testing.T) {
				device, handler := startPacketStack(t, name, mtu)
				payload := bytes.Repeat([]byte{0xa5}, size)
				packets := udpFragments(payload, mtu, 3)
				if reverse {
					for i, j := 0, len(packets)-1; i < j; i, j = i+1, j-1 {
						packets[i], packets[j] = packets[j], packets[i]
					}
				}
				for _, p := range packets {
					device.in <- p
				}
				awaitDatagram(t, handler, payload)
				awaitReply(t, device, payload)
			})
		}
	}
}
