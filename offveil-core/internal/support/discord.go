package support

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" // RFC 6455 WebSocket accept, not a security digest.
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
)

// DiscordConnectivity describes public, unauthenticated endpoint checks. It is
// deliberately separate from the engine's policy probes: failures never change
// routing, DNS, protection state or the strategy cache.
type DiscordConnectivity struct {
	CheckedAt string         `json:"checked_at"`
	Route     string         `json:"route"`
	Updater   string         `json:"updater_platform"`
	Results   []DiscordCheck `json:"results"`
}

type DiscordCheck struct {
	Role       string `json:"role"`
	Host       string `json:"host"`
	Family     string `json:"family"`
	Outcome    string `json:"outcome"`
	Stage      string `json:"stage"`
	ErrorClass string `json:"error_class,omitempty"`
	Addresses  int    `json:"address_count"`
	Attempts   int    `json:"attempts"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Bytes      int    `json:"sample_bytes,omitempty"`
	ElapsedMS  int64  `json:"elapsed_ms"`
}

type discordEndpoint struct {
	role, url string
}

type discordNetwork struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	// Only tests supply a private root CA; production always verifies system roots.
	tlsConfig *tls.Config
}

// DiscordCheckBudget covers two bounded phases: public endpoints, then a sample
// from the download URL in the manifest. Normal support collection is unchanged.
const DiscordCheckBudget = 26 * time.Second

// CheckDiscord uses the OS resolver and ordinary TCP routes, with no HTTP proxy.
// IPv4 and IPv6 are measured independently. This models endpoint reachability,
// not Discord's TLS fingerprint, per-process firewall policy or an account login.
// The updater request is explicitly for Windows stable x64, on every platform.
func CheckDiscord(ctx context.Context) DiscordConnectivity {
	resolver := &net.Resolver{PreferGo: false}
	dialer := &net.Dialer{}
	return checkDiscord(ctx, discordNetwork{lookup: resolver.LookupNetIP, dial: dialer.DialContext})
}

func checkDiscord(ctx context.Context, network discordNetwork) DiscordConnectivity {
	ctx, cancel := context.WithTimeout(ctx, DiscordCheckBudget)
	defer cancel()
	endpoints := []discordEndpoint{
		{"web", "https://discord.com/"},
		{"api", "https://discord.com/api/v10/gateway"},
		{"update_manifest", "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=win&arch=x64"},
		{"gateway", "https://gateway.discord.gg/?v=10&encoding=json"},
	}
	report := DiscordConnectivity{CheckedAt: time.Now().UTC().Format(time.RFC3339), Route: "os_resolver_tcp_no_http_proxy", Updater: "win/x64"}
	report.Results = make([]DiscordCheck, len(endpoints)*2+2)
	downloads := make([]string, len(endpoints)*2)
	var wg sync.WaitGroup
	for i, endpoint := range endpoints {
		for j, family := range []string{"ipv4", "ipv6"} {
			index := i*2 + j
			wg.Go(func() {
				report.Results[index], downloads[index] = checkDiscordEndpoint(ctx, endpoint, family, network)
			})
		}
	}
	wg.Wait()
	download := ""
	for _, candidate := range downloads {
		if candidate != "" {
			download = candidate
			break
		}
	}
	for j, family := range []string{"ipv4", "ipv6"} {
		index := len(endpoints)*2 + j
		if download == "" {
			report.Results[index] = DiscordCheck{Role: "update_download", Host: "stable.dl2.discordapp.net", Family: family, Outcome: "skipped_manifest_unavailable", Stage: "manifest"}
			continue
		}
		wg.Go(func() {
			report.Results[index], _ = checkDiscordEndpoint(ctx, discordEndpoint{"update_download", download}, family, network)
		})
	}
	wg.Wait()
	return report
}

func checkDiscordEndpoint(parent context.Context, endpoint discordEndpoint, family string, network discordNetwork) (result DiscordCheck, download string) {
	start := time.Now()
	defer func() { result.ElapsedMS = time.Since(start).Milliseconds() }()
	u, err := url.Parse(endpoint.url)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		result.Outcome, result.Stage = "invalid_endpoint", "request"
		return
	}
	result.Role, result.Host, result.Family = endpoint.role, u.Hostname(), family
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	ipNetwork, tcpNetwork := "ip4", "tcp4"
	if family == "ipv6" {
		ipNetwork, tcpNetwork = "ip6", "tcp6"
	}
	result.Stage, result.Outcome = "dns", "dns_error"
	addrs, err := network.lookup(ctx, ipNetwork, result.Host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			result.Outcome = "no_address"
		} else {
			result.ErrorClass = discordErrorClass(err)
		}
		return
	}
	poison := offdns.DefaultPoisonSet()
	var candidates []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, addr := range addrs {
		addr = addr.Unmap()
		if (family == "ipv4") != addr.Is4() || !addr.IsValid() || seen[addr] {
			continue
		}
		seen[addr] = true
		result.Addresses++
		if _, hit := poison.Match(addr); hit {
			result.Outcome = "dns_poison"
			return
		}
		// An endpoint can never instruct the support command to contact LAN or
		// loopback services. No returned addresses or raw errors enter the ZIP.
		if !addr.IsGlobalUnicast() || addr.IsPrivate() {
			result.Outcome = "dns_non_public"
			return
		}
		candidates = append(candidates, addr)
	}
	if len(candidates) == 0 {
		result.Outcome = "no_address"
		return
	}
	for i, addr := range candidates {
		if i >= 2 {
			break
		}
		if ctx.Err() != nil {
			result.ErrorClass = discordErrorClass(ctx.Err())
			break
		}
		result.Attempts++
		attempt, attemptCancel := context.WithTimeout(ctx, 6*time.Second)
		result.Stage, result.Outcome = "tcp", "tcp_error"
		result.ErrorClass = ""
		raw, err := network.dial(attempt, tcpNetwork, net.JoinHostPort(addr.String(), "443"))
		if err == nil {
			download = discordRequest(attempt, raw, u, endpoint.role, network.tlsConfig, &result)
		} else {
			result.ErrorClass = discordErrorClass(err)
		}
		if result.Outcome != "ok" && attempt.Err() != nil {
			result.ErrorClass = discordErrorClass(attempt.Err())
		}
		attemptCancel()
		if result.Outcome == "ok" || result.HTTPStatus != 0 {
			break
		}
	}
	return
}

func discordRequest(ctx context.Context, raw net.Conn, u *url.URL, role string, config *tls.Config, result *DiscordCheck) string {
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if config != nil {
		cfg = config.Clone()
	}
	cfg.ServerName = u.Hostname()
	conn := tls.Client(raw, cfg)
	result.Stage, result.Outcome = "tls", "tls_error"
	if err := conn.HandshakeContext(ctx); err != nil {
		result.ErrorClass = discordErrorClass(err)
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		result.Stage, result.Outcome = "request", "invalid_endpoint"
		return ""
	}
	req.Close = true
	req.Header.Set("User-Agent", "offveil-support/1")
	key := ""
	if role == "gateway" {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			result.Stage, result.Outcome = "websocket", "websocket_error"
			return ""
		}
		key = base64.StdEncoding.EncodeToString(nonce)
		req.Close = false
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", key)
	}
	if role == "update_download" {
		req.Header.Set("Range", "bytes=0-1023")
	}
	result.Stage, result.Outcome = "http", "http_error"
	if err := req.Write(conn); err != nil {
		result.ErrorClass = discordErrorClass(err)
		return ""
	}
	// Bound even malformed response headers. Never follow redirects or retain
	// response text, headers, cookies, IPs, error messages or download URLs.
	reader := bufio.NewReader(io.LimitReader(conn, 320<<10))
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		result.ErrorClass = discordErrorClass(err)
		return ""
	}
	// Close raw instead of draining resp.Body: a server may ignore Range and
	// send a whole installer. At most 1 KiB of it is read below.
	result.HTTPStatus = resp.StatusCode
	result.Outcome = "http_status"
	if role == "gateway" {
		result.Stage = "websocket"
		if resp.StatusCode == http.StatusSwitchingProtocols && validDiscordUpgrade(resp.Header, key) {
			result.Outcome = "ok"
		}
		return ""
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	switch role {
	case "update_manifest":
		result.Stage, result.Outcome = "manifest", "invalid_manifest"
		body, err := io.ReadAll(io.LimitReader(resp.Body, (256<<10)+1))
		if err != nil || len(body) > 256<<10 {
			if err != nil {
				result.ErrorClass = discordErrorClass(err)
			}
			return ""
		}
		var manifest struct {
			Full struct {
				URL string `json:"url"`
			} `json:"full"`
		}
		if json.Unmarshal(body, &manifest) != nil || !safeDiscordDownload(manifest.Full.URL) {
			return ""
		}
		result.Outcome = "ok"
		return manifest.Full.URL
	case "update_download":
		result.Stage, result.Outcome = "download", "download_error"
		n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		result.Bytes = int(n)
		if err != nil || n == 0 {
			if err != nil {
				result.ErrorClass = discordErrorClass(err)
			}
			return ""
		}
	}
	result.Outcome = "ok"
	return ""
}

func discordErrorClass(err error) string {
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
	return "other"
}

func safeDiscordDownload(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == "stable.dl2.discordapp.net" &&
		u.User == nil && u.RawQuery == "" && u.Fragment == "" && strings.HasPrefix(u.Path, "/distro/app/stable/win/x64/")
}

func validDiscordUpgrade(header http.Header, key string) bool {
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(digest[:]) || !strings.EqualFold(header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}
