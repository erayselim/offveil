package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"
)

// Use an in-memory connection: no live DNS, privileged certificates or ports.
func silentTLSPeer(t *testing.T) (net.Conn, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"probe.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	client, peer := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer peer.Close()
		server := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
		if server.Handshake() != nil {
			return
		}
		var request [1]byte
		if n, _ := server.Read(request[:]); n > 0 {
			t.Error("TLS liveness probe sent application data")
		}
	}()
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close(); <-done })
	return client, &tls.Config{ServerName: "probe.test", RootCAs: roots, MinVersion: tls.VersionTLS12}
}

func TestTLSProbeDoesNotWaitForUnsolicitedApplicationData(t *testing.T) {
	raw, cfg := silentTLSPeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	began := time.Now()
	if err := tlsHandshake(ctx, raw, cfg); err != nil {
		t.Fatal(err)
	}
	if time.Since(began) > time.Second {
		t.Fatal("successful TLS waited for application data")
	}
}

func TestTLSProbeStillValidatesCertificates(t *testing.T) {
	raw, cfg := silentTLSPeer(t)
	cfg.RootCAs = x509.NewCertPool()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tlsHandshake(ctx, raw, cfg); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestTLSProbeHonorsDeadlineWithSilentPeer(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	began := time.Now()
	if err := tlsHandshake(ctx, raw, &tls.Config{ServerName: "probe.test", MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("silent peer passed")
	}
	if time.Since(began) > time.Second {
		t.Fatal("TLS probe ignored deadline")
	}
}
