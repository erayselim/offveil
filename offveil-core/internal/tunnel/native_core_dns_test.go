package tunnel

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/proc"
	mdns "github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

// Exercise the pinned binary's DNS hijack -> core TCP stub contract. Only the
// SOCKS inbound runs: this fixture cannot install TUN routes or system DNS.
func TestNativeHijackedDNSUsesCoreStub(t *testing.T) {
	bin := os.Getenv("OFFVEIL_SINGBOX_TEST")
	if bin == "" {
		t.Skip("set OFFVEIL_SINGBOX_TEST to the pinned sing-box binary")
	}
	stubListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int32
	stub := &mdns.Server{Listener: stubListener, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, question *mdns.Msg) {
		queries.Add(1)
		answer := new(mdns.Msg).SetReply(question)
		if len(question.Question) == 1 && question.Question[0].Qtype == mdns.TypeA {
			answer.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: question.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 99)}}
		}
		_ = w.WriteMsg(answer)
	})}
	stubDone := make(chan struct{})
	go func() { defer close(stubDone); _ = stub.ActivateAndServe() }()
	defer func() { _ = stub.Shutdown(); _ = stubListener.Close(); <-stubDone }()
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserved.Addr().(*net.TCPAddr).Port
	_ = reserved.Close()
	build, err := BuildSingBox(BuildParams{Provider: ProviderDesync, EnableTUN: true, ListenPort: port, DNSAddress: stubListener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(build.JSON, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["inbounds"] = cfg["inbounds"].([]any)[:1]
	cfg["route"].(map[string]any)["auto_detect_interface"] = false
	cfg["log"].(map[string]any)["level"] = "debug"
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dns-fixture.json")
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
	socks := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := proc.WaitTCP(socks, 3*time.Second, child); err != nil {
		t.Fatalf("startup: %v %s", err, tail.String())
	}
	dialer, err := proxy.SOCKS5("tcp", socks, nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", "192.0.2.53:53")
	if err != nil {
		t.Fatalf("SOCKS: %v %s", err, tail.String())
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	dnsConn := &mdns.Conn{Conn: conn}
	question := new(mdns.Msg).SetQuestion("offveil-fixture.test.", mdns.TypeA)
	if err := dnsConn.WriteMsg(question); err != nil {
		t.Fatal(err)
	}
	answer, err := dnsConn.ReadMsg()
	if err != nil {
		t.Fatalf("DNS: %v %s", err, tail.String())
	}
	if queries.Load() == 0 || len(answer.Answer) != 1 || answer.Answer[0].(*mdns.A).A.String() != "192.0.2.99" {
		t.Fatalf("query bypassed core stub: %+v", answer)
	}
}
