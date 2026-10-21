package support

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// A real local TLS/HTTP origin exercises the pipeline. Only DNS and the dial
// destination are replaced, avoiding external requests and host route changes.
func testNetworkTransport(t *testing.T, handler http.HandlerFunc) networkTransport {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return networkTransport{
		lookup: func(_ context.Context, family, _ string) ([]netip.Addr, error) {
			if family == "ip6" {
				return nil, nil
			}
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		},
		dial: func(ctx context.Context, family, target string) (net.Conn, error) {
			if family != "tcp4" || target != "1.1.1.1:443" {
				return nil, fmt.Errorf("unexpected fixture destination")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp4", server.Listener.Addr().String())
		},
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// httptest's fixture CA and name are verified explicitly because
			// the three public control names all dial the same owned origin.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: "example.com"})
				return err
			},
		},
	}
}

func testNetworkEndpoint(t *testing.T, raw string) networkEndpoint {
	t.Helper()
	endpoint, err := parseNetworkURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.role = "custom_url_1"
	return endpoint
}

func TestNetworkControlsAndBoundedBody(t *testing.T) {
	var calls, unexpected atomic.Int32
	transport := testNetworkTransport(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Range") != "bytes=0-1023" {
			unexpected.Add(1)
		}
		w.Header().Set("Set-Cookie", "session=secret")
		w.Header().Set("Content-Length", "1000000000")
		_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
	})
	report := checkNetwork(context.Background(), NetworkOptions{URLs: []string{"https://public.example.com/private-path?token=secret"}}, transport)
	if len(report.Results) != 8 || calls.Load() != 4 || unexpected.Load() != 0 {
		t.Fatalf("unexpected requests/results: %+v, calls=%d", report, calls.Load())
	}
	for _, result := range report.Results {
		want := "ok"
		if result.Family == "ipv6" {
			want = "no_address"
		}
		if result.Outcome != want {
			t.Fatalf("%+v", result)
		}
		if result.Family == "ipv4" {
			if result.Stage != "body" || result.Bytes != networkSampleSize || result.Attempts != 1 || result.DNS.Outcome != "ok" || len(result.History[0].Stages) != 4 {
				t.Fatalf("missing staged/bounded result: %+v", result)
			}
			for _, stage := range result.History[0].Stages {
				if stage.Outcome != "ok" {
					t.Fatalf("%+v", result)
				}
			}
		}
	}
	raw, err := json.Marshal(diag.ScrubTree(report))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"1.1.1.1", "private-path", "token", "secret", "Set-Cookie", "Authorization"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("report leaked %q", private)
		}
	}
}

func TestNetworkHTTPStatusAndNoRedirects(t *testing.T) {
	for _, status := range []int{204, 206, 302, 401, 403, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			transport := testNetworkTransport(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "https://127.0.0.1/private?token=secret")
				w.WriteHeader(status)
			})
			result := checkNetworkEndpoint(context.Background(), testNetworkEndpoint(t, "https://public.example.com/"), "ipv4", transport)
			want := "http_status"
			if status >= 200 && status < 300 {
				want = "ok"
			}
			if result.Outcome != want || result.HTTPStatus != status || result.ErrorClass != "" || calls.Load() != 1 {
				t.Fatalf("%+v calls=%d", result, calls.Load())
			}
			if result.History[0].Stages[1].Name != "tls" || result.History[0].Stages[1].Outcome != "ok" || result.History[0].Stages[2].Outcome != "ok" {
				t.Fatalf("HTTP status mislabeled as a transport failure: %+v", result)
			}
		})
	}
}

func TestNetworkBodyFailureDoesNotBecomeTLSSuccess(t *testing.T) {
	transport := testNetworkTransport(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("short"))
	})
	result := checkNetworkEndpoint(context.Background(), testNetworkEndpoint(t, "https://public.example.com/"), "ipv4", transport)
	if result.Stage != "body" || result.Outcome != "body_error" || result.ErrorClass != "unexpected_eof" || result.HTTPStatus != 200 || result.Bytes != 5 {
		t.Fatalf("%+v", result)
	}
	if result.History[0].Stages[1].Outcome != "ok" || result.History[0].Stages[3].Outcome != "error" {
		t.Fatalf("lost distinction between TLS and body: %+v", result)
	}
}

func TestNetworkHTTPSExplicitPortAndHTTPRequest(t *testing.T) {
	var requests atomic.Int32
	transport := testNetworkTransport(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != "public.example.com:8443" || r.URL.Path != "/chosen-resource" || r.URL.RawQuery != "token=secret" {
			t.Errorf("request did not use the explicit URL")
		}
		w.WriteHeader(204)
	})
	originalDial := transport.dial
	transport.dial = func(ctx context.Context, family, address string) (net.Conn, error) {
		if address != "1.1.1.1:8443" {
			t.Errorf("guessed a port: %s", address)
		}
		return originalDial(ctx, family, "1.1.1.1:443")
	}
	result := checkNetworkEndpoint(context.Background(), testNetworkEndpoint(t, "https://public.example.com:8443/chosen-resource?token=secret"), "ipv4", transport)
	if result.Outcome != "ok" || result.Port != "8443" || requests.Load() != 1 {
		t.Fatalf("%+v", result)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "chosen-resource") {
		t.Fatalf("URL details were saved: %s", encoded)
	}
}

func TestNetworkHTTPEOFIsSeparateFromVerifiedTLS(t *testing.T) {
	transport := testNetworkTransport(t, func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_ = conn.Close()
	})
	result := checkNetworkEndpoint(context.Background(), testNetworkEndpoint(t, "https://public.example.com/"), "ipv4", transport)
	if result.Stage != "http" || result.Outcome != "http_error" || result.ErrorClass != "unexpected_eof" || result.HTTPStatus != 0 || result.History[0].Stages[1].Outcome != "ok" {
		t.Fatalf("%+v", result)
	}
}

func TestNetworkRawTCPUsesOnlyExplicitPortAndSendsNothing(t *testing.T) {
	endpoint := networkEndpoint{role: "custom_tcp_1", protocol: "tcp", host: "public.example.com", port: "5223"}
	var dialed atomic.Int32
	peerDone := make(chan struct{})
	transport := networkTransport{
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		},
		dial: func(_ context.Context, family, address string) (net.Conn, error) {
			dialed.Add(1)
			if family != "tcp4" || address != "1.1.1.1:5223" {
				t.Errorf("unexpected target %s %s", family, address)
			}
			a, b := net.Pipe()
			go func() {
				defer close(peerDone)
				defer b.Close()
				_ = b.SetReadDeadline(time.Now().Add(time.Second))
				buffer := make([]byte, 1)
				if n, _ := b.Read(buffer); n != 0 {
					t.Error("raw TCP probe sent application bytes")
				}
			}()
			return a, nil
		},
	}
	result := checkNetworkEndpoint(context.Background(), endpoint, "ipv4", transport)
	<-peerDone
	if result.Outcome != "tcp_connected" || result.Stage != "tcp" || result.HTTPStatus != 0 || len(result.History[0].Stages) != 1 || dialed.Load() != 1 {
		t.Fatalf("%+v", result)
	}
}

func TestNetworkRejectsUnsafeTargetsBeforeAnyTraffic(t *testing.T) {
	for _, raw := range []string{
		"http://example.com/", "https://user:secret@example.com/", "https://example.com/#fragment",
		"https://localhost/", "https://machine.local/", "https://machine.internal/", "https://machine.home.arpa/",
		"https://127.0.0.1/", "https://[::1]/", "https://[::ffff:127.0.0.1]/", "https://[64:ff9b::7f00:1]/",
		"https://100.64.0.1/", "https://169.254.169.254/", "https://10.0.0.1/", "https://192.0.2.1/",
		"https://[2002:7f00:1::1]/", "https://[2001:db8::1]/", "https://example.com:0/", "https://example.com:65536/",
		"https://bad_label.example/", "https://-bad.example/", "https://example..com/", "https://2130706433/", "https://example.com:/",
		"https://example.com/" + strings.Repeat("x", 4096),
	} {
		t.Run(raw[:min(len(raw), 90)], func(t *testing.T) {
			var lookups atomic.Int32
			report := checkNetwork(context.Background(), NetworkOptions{URLs: []string{raw}}, networkTransport{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				lookups.Add(1)
				return nil, nil
			}})
			if report.ErrorClass != "invalid_options" || lookups.Load() != 0 {
				t.Fatalf("unsafe request accepted: %+v", report)
			}
		})
	}
	for _, raw := range []string{"example.com", "localhost:80", "127.0.0.1:443", "[::1]:80", "example.com:0", "example.com:65536", "user@example.com:443", "example.com:00443"} {
		if ValidateNetworkOptions(NetworkOptions{TCP: []string{raw}}) == nil {
			t.Fatalf("accepted TCP target %q", raw)
		}
	}
	if ValidateNetworkOptions(NetworkOptions{URLs: make([]string, maxNetworkTargets+1)}) == nil {
		t.Fatal("unbounded target list accepted")
	}
}

func TestNetworkDNSRejectsNonPublicAndPoisonAnswers(t *testing.T) {
	for _, raw := range []string{"195.175.254.2", "127.0.0.1", "192.168.1.1", "100.64.0.1", "198.18.0.1", "169.254.169.254", "224.0.0.1", "::1", "fd00::1", "fe80::1", "2001:db8::1", "2002:7f00:1::1", "64:ff9b::7f00:1", "3fff::1"} {
		t.Run(raw, func(t *testing.T) {
			addr := netip.MustParseAddr(raw)
			family := "ipv4"
			if addr.Is6() {
				family = "ipv6"
			}
			transport := networkTransport{
				lookup: func(context.Context, string, string) ([]netip.Addr, error) { return []netip.Addr{addr}, nil },
				dial: func(context.Context, string, string) (net.Conn, error) {
					t.Error("unsafe DNS answer dialed")
					return nil, errors.New("unexpected")
				},
			}
			result := checkNetworkEndpoint(context.Background(), testNetworkEndpoint(t, "https://public.example.com/"), family, transport)
			want := "dns_non_public"
			if raw == "195.175.254.2" {
				want = "dns_poison"
			}
			if result.Outcome != want || result.Stage != "dns" || result.Attempts != 0 {
				t.Fatalf("%+v", result)
			}
		})
	}
	transport := networkTransport{
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")}, nil
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("public member of mixed public/private answer was dialed")
			return nil, errors.New("unexpected")
		},
	}
	result := checkNetworkEndpoint(context.Background(), testNetworkEndpoint(t, "https://public.example.com/"), "ipv4", transport)
	if result.Outcome != "dns_non_public" || result.Attempts != 0 {
		t.Fatalf("%+v", result)
	}
}

func TestNetworkRetriesPinnedAddressesAndRetainsAttemptStages(t *testing.T) {
	transport := testNetworkTransport(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	originalDial := transport.dial
	var lookupCalls atomic.Int32
	transport.lookup = func(_ context.Context, family, host string) ([]netip.Addr, error) {
		lookupCalls.Add(1)
		return []netip.Addr{netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("1.1.1.1")}, nil
	}
	transport.dial = func(ctx context.Context, family, addr string) (net.Conn, error) {
		if addr == "1.0.0.1:443" {
			return nil, syscall.ECONNRESET
		}
		return originalDial(ctx, family, addr)
	}
	result := checkNetworkEndpoint(context.Background(), testNetworkEndpoint(t, "https://public.example.com/"), "ipv4", transport)
	if result.Outcome != "ok" || result.Attempts != 2 || lookupCalls.Load() != 1 || len(result.History) != 2 || result.History[0].ErrorClass != "reset" || result.History[0].Stage != "tcp" {
		t.Fatalf("%+v lookups=%d", result, lookupCalls.Load())
	}
}

func TestNetworkIPv6AndMissingAAAA(t *testing.T) {
	transport := testNetworkTransport(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	originalDial := transport.dial
	transport.lookup = func(_ context.Context, family, _ string) ([]netip.Addr, error) {
		if family != "ip6" {
			t.Errorf("lookup family=%s", family)
		}
		return []netip.Addr{netip.MustParseAddr("2606:4700::1111")}, nil
	}
	transport.dial = func(ctx context.Context, family, addr string) (net.Conn, error) {
		if family != "tcp6" || addr != "[2606:4700::1111]:443" {
			t.Errorf("dial %s %s", family, addr)
		}
		return originalDial(ctx, "tcp4", "1.1.1.1:443")
	}
	endpoint := testNetworkEndpoint(t, "https://public.example.com/")
	result := checkNetworkEndpoint(context.Background(), endpoint, "ipv6", transport)
	if result.Outcome != "ok" || result.Addresses != 1 {
		t.Fatalf("%+v", result)
	}
	transport.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, &net.DNSError{IsNotFound: true}
	}
	result = checkNetworkEndpoint(context.Background(), endpoint, "ipv6", transport)
	if result.Outcome != "no_address" || result.Attempts != 0 || result.Stage != "dns" {
		t.Fatalf("%+v", result)
	}
}

func TestNetworkRejectsUntrustedCertificateBeforeHTTP(t *testing.T) {
	transport := testNetworkTransport(t, func(w http.ResponseWriter, r *http.Request) { t.Error("HTTP before certificate verification") })
	transport.tlsConfig = &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	result := checkNetworkEndpoint(context.Background(), testNetworkEndpoint(t, "https://public.example.com/"), "ipv4", transport)
	if result.Stage != "tls" || result.Outcome != "tls_error" || result.ErrorClass != "certificate" || result.HTTPStatus != 0 {
		t.Fatalf("%+v", result)
	}
}

func TestNetworkCancellationDuringTLSAndBody(t *testing.T) {
	for _, phase := range []string{"tls", "body"} {
		t.Run(phase, func(t *testing.T) {
			transport := testNetworkTransport(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "100")
				_, _ = w.Write([]byte("x"))
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			})
			if phase == "tls" {
				transport.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					a, b := net.Pipe()
					go func() { <-ctx.Done(); _ = b.Close() }()
					return a, nil
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			result := checkNetworkEndpoint(ctx, testNetworkEndpoint(t, "https://public.example.com/"), "ipv4", transport)
			if result.Stage != phase || result.ErrorClass != "timeout" || time.Since(start) > time.Second {
				t.Fatalf("%+v", result)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var lookups atomic.Int32
	report := checkNetwork(ctx, NetworkOptions{}, networkTransport{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return nil, nil
	}})
	if lookups.Load() != 0 || len(report.Results) != 6 {
		t.Fatalf("cancelled report %+v", report)
	}
	for _, result := range report.Results {
		if result.ErrorClass != "cancelled" {
			t.Fatalf("lost cancellation: %+v", result)
		}
	}
}

func TestNetworkLiteralAddressesAndPrivateErrorStringsAreNeverExported(t *testing.T) {
	endpoint := networkEndpoint{role: "custom_tcp_1", protocol: "tcp", host: "2606:4700::1111", port: "443"}
	transport := networkTransport{
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("C:\\Users\\private 2606:4700::1111 token=secret")
		},
	}
	result := checkNetworkEndpoint(context.Background(), endpoint, "ipv6", transport)
	raw, _ := json.Marshal(result)
	for _, private := range []string{"2606:4700::1111", "private", "secret"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("leaked %q: %s", private, raw)
		}
	}
}

func TestNetworkErrorClasses(t *testing.T) {
	for _, tc := range []struct {
		err   error
		class string
	}{
		{context.Canceled, "cancelled"}, {context.DeadlineExceeded, "timeout"},
		{syscall.ECONNRESET, "reset"}, {syscall.ECONNREFUSED, "refused"},
		{x509.UnknownAuthorityError{}, "certificate"}, {io.EOF, "eof"}, {io.ErrUnexpectedEOF, "unexpected_eof"},
		{tls.RecordHeaderError{}, "tls_protocol"}, {errors.New("C:\\Users\\private token=secret"), "other"},
	} {
		if got := networkErrorClass(tc.err); got != tc.class {
			t.Fatalf("got %s want %s", got, tc.class)
		}
	}
}
