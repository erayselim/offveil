package support

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
)

const testDiscordDownload = "https://stable.dl2.discordapp.net/distro/app/stable/win/x64/1.0.1/full.distro"

// A local TLS origin exercises the real DNS -> TCP -> verified TLS -> HTTP
// pipeline without contacting Discord or changing the machine's DNS/routes.
func discordTestNetwork(t *testing.T, handler http.HandlerFunc) discordNetwork {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return discordNetwork{
		lookup: func(_ context.Context, network, _ string) ([]netip.Addr, error) {
			if network == "ip6" {
				return nil, nil
			}
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		},
		dial: func(ctx context.Context, network, target string) (net.Conn, error) {
			if network != "tcp4" || target != "1.1.1.1:443" {
				return nil, fmt.Errorf("unexpected dial")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp4", server.Listener.Addr().String())
		},
		tlsConfig: &tls.Config{
			RootCAs: pool,
			// The httptest certificate is valid for example.com. Still verify
			// its chain; only the fixture's name differs from the public hosts.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: "example.com"})
				return err
			},
		},
	}
}

func TestDiscordManifestAndBoundedDownload(t *testing.T) {
	var rangeSeen atomic.Bool
	var unexpected atomic.Int32
	network := discordTestNetwork(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Method != "GET" {
			unexpected.Add(1)
		}
		switch r.Host {
		case "updates.discord.com":
			if r.URL.RawQuery != "channel=stable&platform=win&arch=x64" {
				unexpected.Add(1)
			}
			fmt.Fprintf(w, `{"full":{"url":%q}}`, testDiscordDownload)
		case "stable.dl2.discordapp.net":
			rangeSeen.Store(r.Header.Get("Range") == "bytes=0-1023")
			// Ignore Range, as a CDN is permitted to do. The checker must
			// stop at 1 KiB without draining a complete installer.
			w.Header().Set("Content-Length", "1000000000")
			_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
		case "gateway.discord.gg":
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			digest := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(digest[:]))
		default:
			_, _ = w.Write([]byte(`{"url":"wss://gateway.discord.gg"}`))
		}
	})
	report := checkDiscord(context.Background(), network)
	if len(report.Results) != 10 || !rangeSeen.Load() || unexpected.Load() != 0 {
		t.Fatalf("unexpected requests/results: %+v", report)
	}
	for _, result := range report.Results {
		want := "ok"
		if result.Family == "ipv6" {
			want = "no_address"
		}
		if result.Outcome != want {
			t.Fatalf("%+v", result)
		}
		if result.Role == "update_download" && result.Family == "ipv4" && result.Bytes != 1024 {
			t.Fatalf("download was not capped: %+v", result)
		}
	}
	// The report can pass through the existing support ZIP scrubber without
	// exposing addresses or the versioned download URL.
	raw, err := json.Marshal(diag.ScrubTree(report))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"1.1.1.1", "full.distro", "Set-Cookie", "Authorization"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("report leaked %q", private)
		}
	}
}

func TestDiscordFailureStagesAndNoRedirects(t *testing.T) {
	for _, tc := range []struct {
		name, role, response, outcome, stage string
		status                               int
	}{
		{"rate_limited", "web", "", "http_status", "http", 429},
		{"redirect", "update_manifest", "", "http_status", "http", 302},
		{"bad_manifest", "update_manifest", "not json", "invalid_manifest", "manifest", 200},
		{"unsafe_download", "update_manifest", `{"full":{"url":"https://127.0.0.1/private"}}`, "invalid_manifest", "manifest", 200},
		{"empty_download", "update_download", "", "download_error", "download", 200},
		{"bad_upgrade", "gateway", "", "http_status", "websocket", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			network := discordTestNetwork(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "https://127.0.0.1/private")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.response))
			})
			result, download := checkDiscordEndpoint(context.Background(), discordEndpoint{tc.role, "https://updates.discord.com/"}, "ipv4", network)
			if result.Outcome != tc.outcome || result.Stage != tc.stage || result.HTTPStatus != tc.status || download != "" || calls.Load() != 1 {
				t.Fatalf("%+v download=%s calls=%d", result, download, calls.Load())
			}
		})
	}
}

func TestDiscordDNSDoesNotDialUnsafeAnswers(t *testing.T) {
	for _, tc := range []struct{ addr, outcome string }{
		{"195.175.254.2", "dns_poison"}, {"127.0.0.1", "dns_non_public"},
		{"192.168.1.1", "dns_non_public"}, {"169.254.1.1", "dns_non_public"},
		{"224.0.0.1", "dns_non_public"}, {"::1", "dns_non_public"}, {"fd00::1", "dns_non_public"},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			addr := netip.MustParseAddr(tc.addr)
			family := "ipv4"
			if addr.Is6() {
				family = "ipv6"
			}
			network := discordNetwork{
				lookup: func(context.Context, string, string) ([]netip.Addr, error) { return []netip.Addr{addr}, nil },
				dial: func(context.Context, string, string) (net.Conn, error) {
					t.Error("unsafe DNS answer dialed")
					return nil, errors.New("unexpected")
				},
			}
			result, _ := checkDiscordEndpoint(context.Background(), discordEndpoint{"web", "https://discord.com/"}, family, network)
			if result.Outcome != tc.outcome || result.Stage != "dns" || result.Attempts != 0 {
				t.Fatalf("%+v", result)
			}
		})
	}
}

func TestDiscordRetryFamilyAndCancellation(t *testing.T) {
	network := discordTestNetwork(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	originalDial := network.dial
	network.lookup = func(_ context.Context, family, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("1.1.1.1")}, nil
	}
	network.dial = func(ctx context.Context, family, addr string) (net.Conn, error) {
		if addr == "1.0.0.1:443" {
			return nil, errors.New("dial failed at 203.0.113.5 for C:\\Users\\private")
		}
		return originalDial(ctx, family, addr)
	}
	result, _ := checkDiscordEndpoint(context.Background(), discordEndpoint{"web", "https://discord.com/"}, "ipv4", network)
	if result.Outcome != "ok" || result.Attempts != 2 {
		t.Fatalf("%+v", result)
	}
	// A peer that accepts TCP but never replies during TLS must be closed when
	// the caller cancels, rather than waiting for the endpoint budget.
	network.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { <-ctx.Done(); _ = b.Close() }()
		return a, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	result, _ = checkDiscordEndpoint(ctx, discordEndpoint{"web", "https://discord.com/"}, "ipv4", network)
	if result.Stage != "tls" || result.Outcome != "tls_error" || time.Since(start) > time.Second {
		t.Fatalf("%+v", result)
	}
}

func TestDiscordRejectsUntrustedCertificate(t *testing.T) {
	network := discordTestNetwork(t, func(w http.ResponseWriter, r *http.Request) { t.Error("HTTP before certificate verification") })
	network.tlsConfig = &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	result, _ := checkDiscordEndpoint(context.Background(), discordEndpoint{"web", "https://discord.com/"}, "ipv4", network)
	if result.Stage != "tls" || result.Outcome != "tls_error" || result.ErrorClass != "certificate" || result.HTTPStatus != 0 {
		t.Fatalf("%+v", result)
	}
}

func TestDiscordIPv6AndMissingAAAA(t *testing.T) {
	network := discordTestNetwork(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	originalDial := network.dial
	network.lookup = func(_ context.Context, family, _ string) ([]netip.Addr, error) {
		if family != "ip6" {
			t.Errorf("lookup family=%s", family)
		}
		return []netip.Addr{netip.MustParseAddr("2606:4700::1111")}, nil
	}
	network.dial = func(ctx context.Context, family, addr string) (net.Conn, error) {
		if family != "tcp6" || addr != "[2606:4700::1111]:443" {
			t.Errorf("dial %s %s", family, addr)
		}
		return originalDial(ctx, "tcp4", "1.1.1.1:443")
	}
	result, _ := checkDiscordEndpoint(context.Background(), discordEndpoint{"web", "https://discord.com/"}, "ipv6", network)
	if result.Outcome != "ok" || result.Addresses != 1 {
		t.Fatalf("%+v", result)
	}
	network.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, &net.DNSError{IsNotFound: true}
	}
	result, _ = checkDiscordEndpoint(context.Background(), discordEndpoint{"web", "https://discord.com/"}, "ipv6", network)
	if result.Outcome != "no_address" || result.Attempts != 0 {
		t.Fatalf("%+v", result)
	}
}

func TestDiscordErrorClassesNeverIncludeRawErrors(t *testing.T) {
	for _, tc := range []struct {
		err   error
		class string
	}{
		{context.Canceled, "cancelled"}, {context.DeadlineExceeded, "timeout"},
		{syscall.ECONNRESET, "reset"}, {syscall.ECONNREFUSED, "refused"},
		{x509.UnknownAuthorityError{}, "certificate"},
		{errors.New("203.0.113.1 C:\\Users\\private token=secret"), "other"},
	} {
		if got := discordErrorClass(tc.err); got != tc.class {
			t.Fatalf("got %s want %s", got, tc.class)
		}
	}
}

func TestDiscordCancellationWhileReadingManifest(t *testing.T) {
	network := discordTestNetwork(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"full":`))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	result, download := checkDiscordEndpoint(ctx, discordEndpoint{"update_manifest", "https://updates.discord.com/"}, "ipv4", network)
	if download != "" || result.Stage != "manifest" || result.Outcome != "invalid_manifest" || result.ErrorClass != "timeout" || time.Since(start) > time.Second {
		t.Fatalf("%+v", result)
	}
}

func TestDiscordDownloadAllowlistAndWebSocketAccept(t *testing.T) {
	if !safeDiscordDownload(testDiscordDownload) {
		t.Fatal("expected public CDN")
	}
	for _, raw := range []string{
		"http://stable.dl2.discordapp.net/distro/app/stable/win/x64/file",
		"https://stable.dl2.discordapp.net.evil.test/distro/app/stable/win/x64/file",
		"https://user:pass@stable.dl2.discordapp.net/distro/app/stable/win/x64/file",
		"https://stable.dl2.discordapp.net:443/distro/app/stable/win/x64/file",
		testDiscordDownload + "?token=secret", testDiscordDownload + "#fragment",
		"https://stable.dl2.discordapp.net/private",
	} {
		if safeDiscordDownload(raw) {
			t.Fatalf("accepted %q", raw)
		}
	}
	header := http.Header{"Connection": {"keep-alive, Upgrade"}, "Upgrade": {"websocket"}, "Sec-Websocket-Accept": {"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}}
	if !validDiscordUpgrade(header, "dGhlIHNhbXBsZSBub25jZQ==") {
		t.Fatal("RFC 6455 example failed")
	}
	header.Set("Sec-WebSocket-Accept", "bad")
	if validDiscordUpgrade(header, "dGhlIHNhbXBsZSBub25jZQ==") {
		t.Fatal("invalid handshake accepted")
	}
}
