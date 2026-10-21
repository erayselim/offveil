package support

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
)

// NetworkCheckBudget bounds the whole check, including optional targets. The
// desktop export allows another eight seconds for collection and ZIP creation.
const NetworkCheckBudget = 24 * time.Second

const (
	maxNetworkTargets = 6 // additional, explicitly supplied targets
	networkWorkers    = 6
	networkSampleSize = 1024
)

// NetworkOptions only adds explicitly supplied destinations. No response body,
// redirect, manifest, domain prefix or guessed port can add another destination.
type NetworkOptions struct {
	URLs []string
	TCP  []string
}

// NetworkConnectivity is independent of routing policy and provider health.
// It measures the OS resolver and actual OS TCP routes, including an active TUN,
// without an HTTP proxy. It does not model an application's TLS fingerprint.
type NetworkConnectivity struct {
	CheckedAt  string         `json:"checked_at"`
	Route      string         `json:"route"`
	ErrorClass string         `json:"error_class,omitempty"`
	Results    []NetworkCheck `json:"results"`
}

type NetworkCheck struct {
	Role       string           `json:"role"`
	Host       string           `json:"host"`
	Port       string           `json:"port"`
	Protocol   string           `json:"protocol"`
	Family     string           `json:"family"`
	Outcome    string           `json:"outcome"`
	Stage      string           `json:"stage"`
	ErrorClass string           `json:"error_class,omitempty"`
	Addresses  int              `json:"address_count"`
	Attempts   int              `json:"attempts"`
	HTTPStatus int              `json:"http_status,omitempty"`
	Bytes      int              `json:"sample_bytes,omitempty"`
	ElapsedMS  int64            `json:"elapsed_ms"`
	DNS        NetworkStage     `json:"dns"`
	History    []NetworkAttempt `json:"attempt_results,omitempty"`
}

// Each address attempt retains its own stages. A successful retry must not hide
// a certificate, reset or partial-body error from an earlier address.
type NetworkAttempt struct {
	Outcome    string         `json:"outcome"`
	Stage      string         `json:"stage"`
	ErrorClass string         `json:"error_class,omitempty"`
	HTTPStatus int            `json:"http_status,omitempty"`
	Bytes      int            `json:"sample_bytes,omitempty"`
	Stages     []NetworkStage `json:"stages"`
}

type NetworkStage struct {
	Name       string `json:"name"`
	Outcome    string `json:"outcome"`
	ErrorClass string `json:"error_class,omitempty"`
	ElapsedMS  int64  `json:"elapsed_ms"`
}

type networkEndpoint struct {
	role, protocol, host, port string
	url                        *url.URL
}

type networkTransport struct {
	lookup    func(context.Context, string, string) ([]netip.Addr, error)
	dial      func(context.Context, string, string) (net.Conn, error)
	tlsConfig *tls.Config // private test roots only; production uses system roots
}

// ValidateNetworkOptions never includes input URLs, addresses or credentials in
// an error. Callers may safely show its errors in a command result.
func ValidateNetworkOptions(options NetworkOptions) error {
	_, err := networkEndpoints(options)
	return err
}

func networkEndpoints(options NetworkOptions) ([]networkEndpoint, error) {
	if len(options.URLs)+len(options.TCP) > maxNetworkTargets {
		return nil, fmt.Errorf("at most %d additional network targets are supported", maxNetworkTargets)
	}
	controls := []string{"https://example.com/", "https://www.wikipedia.org/", "https://www.mozilla.org/"}
	endpoints := make([]networkEndpoint, 0, len(controls)+len(options.URLs)+len(options.TCP))
	for i, raw := range controls {
		endpoint, _ := parseNetworkURL(raw)
		endpoint.role = fmt.Sprintf("control_%d", i+1)
		endpoints = append(endpoints, endpoint)
	}
	for i, raw := range options.URLs {
		endpoint, err := parseNetworkURL(raw)
		if err != nil {
			return nil, fmt.Errorf("check-url target %d is invalid: use a public HTTPS URL without credentials or fragment", i+1)
		}
		endpoint.role = fmt.Sprintf("custom_url_%d", i+1)
		endpoints = append(endpoints, endpoint)
	}
	for i, raw := range options.TCP {
		host, port, err := net.SplitHostPort(raw)
		if err != nil || len(raw) > 4096 || !validNetworkHost(host) || !validNetworkPort(port) {
			return nil, fmt.Errorf("check-tcp target %d is invalid: use a public host:port", i+1)
		}
		endpoints = append(endpoints, networkEndpoint{role: fmt.Sprintf("custom_tcp_%d", i+1), protocol: "tcp", host: strings.ToLower(host), port: port})
	}
	return endpoints, nil
}

func parseNetworkURL(raw string) (networkEndpoint, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 4096 || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.HasSuffix(u.Host, ":") ||
		!validNetworkHost(u.Hostname()) || (u.Port() != "" && !validNetworkPort(u.Port())) {
		return networkEndpoint{}, errors.New("invalid HTTPS target")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return networkEndpoint{protocol: "https", host: strings.ToLower(u.Hostname()), port: port, url: u}, nil
}

func validNetworkPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port
}

func validNetworkHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\\/@?#% \t\r\n") {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return publicNetworkAddress(addr)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if !strings.Contains(host, ".") || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".home.arpa") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

// Go's IsGlobalUnicast includes private, documentation and shared-address
// ranges. Block those as well, and reject transition prefixes that can embed
// private IPv4 destinations. A resolved IP is pinned into the TCP dial: there is
// no second hostname lookup and no redirect, so DNS rebinding cannot change it.
var nonPublicNetworkPrefixes = func() []netip.Prefix {
	ranges := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
	}
	prefixes := make([]netip.Prefix, len(ranges))
	for i, raw := range ranges {
		prefixes[i] = netip.MustParsePrefix(raw)
	}
	return prefixes
}()

func publicNetworkAddress(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || (addr.Is6() && !netip.MustParsePrefix("2000::/3").Contains(addr)) {
		return false
	}
	for _, prefix := range nonPublicNetworkPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// CheckNetwork never changes routes, DNS, policy, account state or provider
// health. Raw TCP checks only establish TCP; HTTPS checks verify certificates,
// read one response and consume at most 1 KiB without following redirects.
func CheckNetwork(ctx context.Context, options NetworkOptions) NetworkConnectivity {
	resolver := &net.Resolver{PreferGo: false}
	dialer := &net.Dialer{}
	return checkNetwork(ctx, options, networkTransport{lookup: resolver.LookupNetIP, dial: dialer.DialContext})
}

func checkNetwork(ctx context.Context, options NetworkOptions, transport networkTransport) NetworkConnectivity {
	ctx, cancel := context.WithTimeout(ctx, NetworkCheckBudget)
	defer cancel()
	report := NetworkConnectivity{CheckedAt: time.Now().UTC().Format(time.RFC3339), Route: "os_resolver_tcp_no_http_proxy"}
	endpoints, err := networkEndpoints(options)
	if err != nil {
		report.ErrorClass = "invalid_options"
		return report
	}
	report.Results = make([]NetworkCheck, len(endpoints)*2)
	jobs := make(chan int, len(report.Results))
	for i := range report.Results {
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	for range networkWorkers {
		wg.Go(func() {
			for index := range jobs {
				family := "ipv4"
				if index%2 != 0 {
					family = "ipv6"
				}
				report.Results[index] = checkNetworkEndpoint(ctx, endpoints[index/2], family, transport)
			}
		})
	}
	wg.Wait()
	return report
}

func checkNetworkEndpoint(parent context.Context, endpoint networkEndpoint, family string, transport networkTransport) (result NetworkCheck) {
	start := time.Now()
	defer func() { result.ElapsedMS = time.Since(start).Milliseconds() }()
	host := endpoint.host
	if _, err := netip.ParseAddr(host); err == nil {
		host = "literal_address" // no IP addresses enter the support bundle
	}
	result = NetworkCheck{Role: endpoint.role, Host: host, Port: endpoint.port, Protocol: endpoint.protocol, Family: family, Stage: "dns", Outcome: "dns_error"}
	result.DNS = NetworkStage{Name: "dns", Outcome: "error"}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	ipNetwork, tcpNetwork := "ip4", "tcp4"
	if family == "ipv6" {
		ipNetwork, tcpNetwork = "ip6", "tcp6"
	}
	if ctx.Err() != nil {
		result.ErrorClass = networkErrorClass(ctx.Err())
		result.DNS.ErrorClass = result.ErrorClass
		return
	}
	addrs, err := transport.lookup(ctx, ipNetwork, endpoint.host)
	result.DNS.ElapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			result.Outcome, result.DNS.Outcome = "no_address", "no_address"
		} else {
			result.ErrorClass = networkErrorClass(err)
			result.DNS.ErrorClass = result.ErrorClass
		}
		return
	}
	poison := offdns.DefaultPoisonSet()
	var candidates []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !addr.IsValid() || (family == "ipv4") != addr.Is4() || seen[addr] {
			continue
		}
		seen[addr] = true
		result.Addresses++
		if _, hit := poison.Match(addr); hit {
			result.Outcome, result.DNS.Outcome = "dns_poison", "dns_poison"
			return
		}
		// Reject an entire mixed public/private answer before dialing any IP.
		if !publicNetworkAddress(addr) {
			result.Outcome, result.DNS.Outcome = "dns_non_public", "dns_non_public"
			return
		}
		candidates = append(candidates, addr)
	}
	if len(candidates) == 0 {
		result.Outcome, result.DNS.Outcome = "no_address", "no_address"
		return
	}
	result.DNS.Outcome = "ok"
	for i, addr := range candidates {
		if i >= 2 || ctx.Err() != nil {
			break
		}
		attemptCtx, attemptCancel := context.WithTimeout(ctx, 4*time.Second)
		attempt := networkAttempt(attemptCtx, endpoint, tcpNetwork, addr, transport)
		attemptCancel()
		result.History = append(result.History, attempt)
		result.Attempts++
		result.Stage, result.Outcome, result.ErrorClass = attempt.Stage, attempt.Outcome, attempt.ErrorClass
		result.HTTPStatus, result.Bytes = attempt.HTTPStatus, attempt.Bytes
		if attempt.Outcome == "ok" || attempt.Outcome == "tcp_connected" || attempt.HTTPStatus != 0 {
			break
		}
	}
	if result.Attempts == 0 && ctx.Err() != nil {
		result.ErrorClass = networkErrorClass(ctx.Err())
	}
	return
}

func networkAttempt(ctx context.Context, endpoint networkEndpoint, family string, addr netip.Addr, transport networkTransport) (result NetworkAttempt) {
	start := time.Now()
	result.Stage, result.Outcome = "tcp", "tcp_error"
	raw, err := transport.dial(ctx, family, net.JoinHostPort(addr.String(), endpoint.port))
	stage := NetworkStage{Name: "tcp", Outcome: "ok", ElapsedMS: time.Since(start).Milliseconds()}
	if err != nil {
		result.ErrorClass = networkErrorClass(err)
		stage.Outcome, stage.ErrorClass = "error", result.ErrorClass
		result.Stages = append(result.Stages, stage)
		return
	}
	result.Stages = append(result.Stages, stage)
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	defer func() {
		if result.Outcome != "ok" && result.Outcome != "tcp_connected" && ctx.Err() != nil {
			result.ErrorClass = networkErrorClass(ctx.Err())
			if len(result.Stages) > 0 {
				result.Stages[len(result.Stages)-1].ErrorClass = result.ErrorClass
			}
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	if endpoint.protocol == "tcp" {
		result.Outcome = "tcp_connected"
		return
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if transport.tlsConfig != nil {
		cfg = transport.tlsConfig.Clone()
	}
	cfg.ServerName = endpoint.host
	conn := tls.Client(raw, cfg)
	start = time.Now()
	result.Stage, result.Outcome = "tls", "tls_error"
	err = conn.HandshakeContext(ctx)
	stage = NetworkStage{Name: "tls", Outcome: "ok", ElapsedMS: time.Since(start).Milliseconds()}
	if err != nil {
		result.ErrorClass = networkErrorClass(err)
		stage.Outcome, stage.ErrorClass = "error", result.ErrorClass
		result.Stages = append(result.Stages, stage)
		return
	}
	result.Stages = append(result.Stages, stage)
	// URLs, paths, query parameters, response headers and bodies are never kept.
	// Certificates remain verified against the requested host and system roots.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.url.String(), nil)
	if err != nil {
		result.Stage, result.Outcome = "request", "invalid_endpoint"
		return
	}
	req.Close = true
	req.Header.Set("User-Agent", "offveil-support/1")
	req.Header.Set("Range", "bytes=0-1023")
	start = time.Now()
	result.Stage, result.Outcome = "http", "http_error"
	err = req.Write(conn)
	var resp *http.Response
	if err == nil {
		// This bounds malformed/oversized headers as well as bytes pulled into
		// the buffer. Raw closure avoids draining an unbounded response body.
		resp, err = http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 32<<10)), req)
	}
	stage = NetworkStage{Name: "http", Outcome: "ok", ElapsedMS: time.Since(start).Milliseconds()}
	if err != nil {
		result.ErrorClass = networkErrorClass(err)
		stage.Outcome, stage.ErrorClass = "error", result.ErrorClass
		result.Stages = append(result.Stages, stage)
		return
	}
	result.HTTPStatus = resp.StatusCode
	result.Stages = append(result.Stages, stage)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Outcome = "http_status"
		return
	}
	start = time.Now()
	result.Stage, result.Outcome = "body", "body_error"
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, networkSampleSize))
	result.Bytes = int(n)
	stage = NetworkStage{Name: "body", Outcome: "ok", ElapsedMS: time.Since(start).Milliseconds()}
	if err != nil {
		result.ErrorClass = networkErrorClass(err)
		stage.Outcome, stage.ErrorClass = "error", result.ErrorClass
	} else {
		result.Outcome = "ok"
	}
	result.Stages = append(result.Stages, stage)
	return
}

func networkErrorClass(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	var networkErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkErr) && networkErr.Timeout()) {
		return "timeout"
	}
	var certErr *tls.CertificateVerificationError
	var unknownCA x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	if errors.As(err, &certErr) || errors.As(err, &unknownCA) || errors.As(err, &hostname) || errors.As(err, &invalidCert) {
		return "certificate"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "reset"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "unexpected_eof"
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return "tls_protocol"
	}
	return "other"
}
