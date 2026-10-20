//go:build windows

package desync

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// Verify actual packet/record transformations against an owned TLS peer.
// Nothing resolves or connects to the public Discord service in this fixture.
func TestNativeNewStrategiesPreserveVerifiedTLS(t *testing.T) {
	bin := os.Getenv("OFFVEIL_BYEDPI_TEST")
	if bin == "" {
		t.Skip("set OFFVEIL_BYEDPI_TEST to the pinned ByeDPI binary")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"discord.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "fixture") }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	ids := map[string]bool{"byedpi:split-sni-mid": true, "byedpi:tlsrec-sni-mid": true, "byedpi:split-tlsrec": true, "byedpi:split-disorder-tlsrec": true}
	for _, strategy := range NativeScanCandidates() {
		if !ids[strategy.ID] {
			continue
		}
		t.Run(strategy.ID, func(t *testing.T) {
			reservation, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.Addr().(*net.TCPAddr).Port
			_ = reservation.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			sess, err := Start(Config{Context: ctx, BinaryPath: bin, ListenPort: port, Strategy: strategy, ConnIP: "127.0.0.1"})
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			dialer, err := proxy.SOCKS5("tcp", sess.SocksAddr(), nil, &net.Dialer{Timeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
			conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "discord.com", MinVersion: tls.VersionTLS12})
			if err := conn.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: discord.com\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(io.LimitReader(response.Body, 64))
			if err != nil || string(body) != "fixture" {
				t.Fatalf("TLS payload corrupted: %q %v", body, err)
			}
		})
	}
}
