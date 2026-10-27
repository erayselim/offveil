package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestWARPBootstrapCannotUseCapturedDefaultTransport(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	captured := 0
	http.DefaultTransport = warpTestTransport(func(*http.Request) (*http.Response, error) {
		captured++
		return nil, errors.New("fixture: default route reaches disconnected TUN")
	})
	resolved := 0
	resolverErr := errors.New("fixture bootstrap resolver reached")
	cfg := Config{Context: context.Background(), DataDir: t.TempDir(),
		Resolve: func(context.Context, string) (netip.Addr, error) {
			resolved++
			return netip.Addr{}, resolverErr
		},
	}
	_, ok, _, err := startOne(cfg, providerAttempt{ID: ProviderWARP})
	if ok || captured != 0 || resolved != 1 || !errors.Is(err, resolverErr) {
		t.Fatalf("provider bootstrap used the captured default path: ok=%t captured=%d resolved=%d err=%v", ok, captured, resolved, err)
	}
}

func TestBootstrapResolutionPreservesTLSIdentityAndIgnoresProxy(t *testing.T) {
	seen := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.TLS.ServerName
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	certificate := server.Certificate()
	if len(certificate.DNSNames) == 0 {
		t.Fatal("TLS fixture needs a DNS identity")
	}
	host := certificate.DNSNames[0]
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	client := newBootstrapHTTPClient(Config{Resolve: func(ctx context.Context, name string) (netip.Addr, error) {
		if name != host && name != "mismatch.invalid" {
			t.Errorf("unexpected bootstrap hostname: %s", name)
		}
		return netip.MustParseAddr("127.0.0.1"), nil
	}})
	defer client.CloseIdleConnections()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	response, err := client.Get("https://" + net.JoinHostPort(host, port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent || <-seen != host {
		t.Fatal("bootstrap changed the TLS hostname or HTTP result")
	}
	if response, err = client.Get("https://" + net.JoinHostPort("mismatch.invalid", port) + "/"); err == nil {
		_ = response.Body.Close()
		t.Fatal("bootstrap skipped certificate hostname verification")
	}
}

func TestBootstrapMissingInterfaceDoesNotUseDefaultRoute(t *testing.T) {
	client := newBootstrapHTTPClient(Config{EgressInterface: "offveil-nonexistent-test-interface"})
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := client.Transport.(*http.Transport).DialContext(ctx, "tcp4", "127.0.0.1:1")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "bootstrap interface") {
		t.Fatalf("missing egress silently used the default route: %v", err)
	}
}

func TestBootstrapResolverSharesRequestDeadline(t *testing.T) {
	client := newBootstrapHTTPClient(Config{Resolve: func(ctx context.Context, _ string) (netip.Addr, error) {
		<-ctx.Done()
		return netip.Addr{}, ctx.Err()
	}})
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://bootstrap.invalid/", nil)
	began := time.Now()
	_, err := client.Do(request)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(began) > time.Second {
		t.Fatalf("bootstrap escaped request cancellation: %v", err)
	}
}
