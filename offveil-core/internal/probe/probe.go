package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"

	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
)

// DefaultTimeout is the per-target probe budget (contracts.md §4.2: ~3-5s).
const DefaultTimeout = 4 * time.Second

// ThrottleThreshold marks suspiciously slow TLS as throttle_suspect.
// OONI TR throttle studies compare target TLS timing vs control baseline.
const ThrottleThreshold = 2500 * time.Millisecond

// MaxDialIPs is how many resolved A records to try (CDN / multi-homed).
const MaxDialIPs = 2

// DefaultControlHost is a clean baseline for differential classification
// (dpi-probe / OONI: clean vs blocked host on comparable path).
const DefaultControlHost = "www.microsoft.com"

// Options configures a short cascade probe.
type Options struct {
	Timeout time.Duration
	Port    string
	DoH     *offdns.DoHClient
	Poison  *offdns.PoisonSet
	// Resolve overrides DoH A lookup (tests).
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// DialTLS overrides the direct TLS dial (tests).
	DialTLS func(ctx context.Context, addr, serverName string) error
	// LookupSystem optionally probes system DNS for poison (tests inject).
	LookupSystem func(host string, poison *offdns.PoisonSet) (addrs []netip.Addr, poisonID string, err error)
	// ControlHost for differential classify (empty = DefaultControlHost; "-" disables).
	ControlHost string
	// SkipControl disables differential probing.
	SkipControl bool
	// VerifyHTTP runs optional HTTP HEAD after open TLS (contracts §4.2 step 4).
	VerifyHTTP bool
	// HTTPHead overrides HTTP verify (tests).
	HTTPHead func(ctx context.Context, host string) error
}

// Target probes one hostname: DoH (+system poison check) → TCP+TLS SNI (multi-IP).
func Target(ctx context.Context, host string, opt Options) Result {
	start := time.Now()
	at := start.UTC()
	res := Result{Target: host, At: at, Class: ClassTimeout, Path: PathFor(ClassTimeout), Confidence: 0.4}

	if host == "" {
		res.Detail = "empty host"
		res.Took = time.Since(start)
		return res
	}

	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	port := opt.Port
	if port == "" {
		port = "443"
	}
	poison := opt.Poison
	if poison == nil {
		poison = offdns.DefaultPoisonSet()
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sysLookup := opt.LookupSystem
	if sysLookup == nil {
		sysLookup = offdns.ProbeSystemDNS
	}
	if _, poisonID, err := sysLookup(host, poison); err == nil && poisonID != "" {
		res.Class = ClassDNSPoison
		res.Detail = "system dns poison: " + poisonID
		res.Confidence = 0.85
		// Continue with DoH - poison alone does not pick the final path.
	}

	resolve := opt.Resolve
	if resolve == nil {
		doh := opt.DoH
		if doh == nil {
			doh = offdns.NewDoHClient(poison)
		}
		resolve = doh.LookupAWithFallback
	}
	addrs, err := resolve(pctx, host)
	if err != nil {
		var pe *offdns.PoisonError
		if errors.As(err, &pe) {
			res.Class = ClassDNSPoison
			res.Detail = pe.Error()
			res.Path = PathFor(res.Class)
			res.Confidence = 0.95
			res.Took = time.Since(start)
			return res
		}
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "nxdomain") || strings.Contains(msg, "no such host") ||
			strings.Contains(msg, "name error") || strings.Contains(msg, "rcode name error") {
			res.Class = ClassDNSPoison
			res.Detail = "resolve nxdomain: " + err.Error()
			res.Path = PathFor(res.Class)
			res.Confidence = 0.8
			res.Took = time.Since(start)
			return res
		}
		res.Class = ClassTimeout
		res.Detail = "resolve: " + err.Error()
		res.Path = PathFor(res.Class)
		res.Took = time.Since(start)
		return res
	}
	if len(addrs) == 0 {
		res.Class = ClassDNSPoison
		res.Detail = "resolve: empty answers"
		res.Path = PathFor(res.Class)
		res.Confidence = 0.75
		res.Took = time.Since(start)
		return res
	}
	if _, id, ok := poison.MatchAny(addrs); ok {
		res.Class = ClassDNSPoison
		res.Detail = "doh poison: " + id
		res.Path = PathFor(res.Class)
		res.Confidence = 0.95
		res.Addrs = addrs
		res.Took = time.Since(start)
		return res
	}
	res.Addrs = addrs

	dialIPs := pickDialIPs(addrs, MaxDialIPs)
	dialTLS := opt.DialTLS
	if dialTLS == nil {
		dialTLS = defaultDialTLS
	}

	var (
		bestClass Class
		bestErr   error
		bestTook  time.Duration
		anyDialOK bool
		tlsOK     bool
	)
	for i, dialIP := range dialIPs {
		tlsStart := time.Now()
		err = dialTLS(pctx, net.JoinHostPort(dialIP.String(), port), host)
		tookTLS := time.Since(tlsStart)
		if err == nil {
			tlsOK = true
			bestTook = tookTLS
			if tookTLS >= ThrottleThreshold {
				bestClass = ClassThrottleSuspect
				bestErr = fmt.Errorf("slow tls %s", tookTLS.Round(time.Millisecond))
			} else {
				bestClass = ClassOpen
				bestErr = nil
			}
			break
		}
		cls := classifyTLSErr(err)
		if cls != ClassIPDrop {
			anyDialOK = true // TCP reached something → not pure IP blackhole
		}
		if i == 0 {
			bestClass = cls
			bestErr = err
			bestTook = tookTLS
		} else {
			// Prefer non-timeout signal; IP drop on all IPs stays ip_drop.
			if bestClass == ClassIPDrop && cls != ClassIPDrop {
				bestClass = cls
				bestErr = err
			}
		}
	}

	if tlsOK {
		if bestClass == ClassThrottleSuspect {
			res.Class = ClassThrottleSuspect
			res.Detail = bestErr.Error()
			res.Confidence = 0.7
		} else if res.Class == ClassDNSPoison {
			res.Class = ClassOpen
			res.Detail = "open after doh (system was poisoned)"
			res.Confidence = 0.9
		} else {
			res.Class = ClassOpen
			res.Detail = ""
			res.Confidence = 0.85
		}
		res.Path = PathFor(res.Class)
		res.OK = true
		res.Took = time.Since(start)

		if opt.VerifyHTTP && res.Class == ClassOpen {
			head := opt.HTTPHead
			if head == nil {
				head = defaultHTTPHead
			}
			hctx, hcancel := context.WithTimeout(pctx, 2*time.Second)
			herr := head(hctx, host)
			hcancel()
			if herr != nil {
				res.Detail = "tls ok; http verify: " + herr.Error()
				res.Confidence = 0.6
				// Keep open/direct - HTTP fail alone is not a block class.
			} else if res.Detail == "" {
				res.Detail = "tls+http ok"
				res.Confidence = 0.95
			}
		}
		return res
	}

	res.Class = bestClass
	if bestClass == ClassIPDrop && anyDialOK {
		// Mixed: some IPs dialable but TLS failed elsewhere → treat as DPI.
		res.Class = ClassDPIReset
		res.Confidence = 0.75
	} else {
		switch bestClass {
		case ClassDPIReset:
			res.Confidence = 0.85
		case ClassIPDrop:
			res.Confidence = 0.8
		default:
			res.Confidence = 0.5
		}
	}
	if res.Detail == "" || strings.HasPrefix(res.Detail, "system dns") {
		if bestErr != nil {
			res.Detail = bestErr.Error()
		}
	}
	_ = bestTook
	res.Path = PathFor(res.Class)
	res.OK = true // classified; path is the cascade choice
	res.Took = time.Since(start)
	return res
}

func pickDialIPs(addrs []netip.Addr, max int) []netip.Addr {
	out := make([]netip.Addr, 0, max)
	for _, a := range addrs {
		if a.Is4() {
			out = append(out, a)
			if len(out) >= max {
				return out
			}
		}
	}
	if len(out) == 0 && len(addrs) > 0 {
		out = append(out, addrs[0])
	}
	return out
}

func defaultDialTLS(ctx context.Context, addr, serverName string) error {
	d := &net.Dialer{Timeout: 3 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	tc := tls.Client(raw, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	_ = tc.Close()
	return nil
}

func defaultHTTPHead(ctx context.Context, host string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+host+"/", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "offveil-probe/2.1")
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// classifyTLSErr maps dial/handshake failures to contracts probe classes.
// Aligned with OONI Web Connectivity: dial timeout → tcp_ip; post-ClientHello RST → DPI.
func classifyTLSErr(err error) Class {
	if err == nil {
		return ClassOpen
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ClassTimeout
	}

	var op *net.OpError
	if errors.As(err, &op) {
		if op.Timeout() {
			// SYN blackhole vs mid-handshake timeout: Op=="dial" → ip_drop.
			if op.Op == "dial" {
				return ClassIPDrop
			}
			return ClassTimeout
		}
		if errors.Is(op.Err, syscall.ECONNRESET) || errors.Is(op.Err, syscall.ECONNABORTED) {
			if op.Op == "dial" {
				return ClassIPDrop
			}
			return ClassDPIReset
		}
		if errors.Is(op.Err, syscall.ECONNREFUSED) || errors.Is(op.Err, syscall.ENETUNREACH) ||
			errors.Is(op.Err, syscall.EHOSTUNREACH) {
			return ClassIPDrop
		}
		msg := strings.ToLower(op.Err.Error())
		if strings.Contains(msg, "forcibly closed") || strings.Contains(msg, "connection reset") {
			if op.Op == "dial" {
				return ClassIPDrop
			}
			return ClassDPIReset
		}
		if strings.Contains(msg, "no route") || strings.Contains(msg, "network is unreachable") {
			return ClassIPDrop
		}
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "timed out"):
		if strings.Contains(msg, "connectex") || strings.Contains(msg, "dial tcp") {
			return ClassIPDrop
		}
		return ClassTimeout
	case strings.Contains(msg, "connection reset"), strings.Contains(msg, "forcibly closed"), strings.Contains(msg, "broken pipe"):
		return ClassDPIReset
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "no route"),
		strings.Contains(msg, "network is unreachable"), strings.Contains(msg, "host is unreachable"):
		return ClassIPDrop
	}

	var te interface{ Timeout() bool }
	if errors.As(err, &te) && te.Timeout() {
		return ClassTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		// Early close after ClientHello ≈ DPI RST (OONI / dpi-probe).
		return ClassDPIReset
	}
	// TLS alert / cert weirdness after TCP up → treat as DPI-ish for cascade.
	if strings.Contains(msg, "tls:") || strings.Contains(msg, "handshake") ||
		strings.Contains(msg, "certificate") || strings.Contains(msg, "first record") {
		return ClassDPIReset
	}
	return ClassTimeout
}

// CuratedHosts is the default probe list (Discord package seed).
func CuratedHosts() []string {
	return []string{"discord.com"}
}

// Session runs probes for curated (or explicit) hosts and builds a Report.
// When control differential is enabled, target failures are strengthened if
// the clean control host is open (OONI/dpi-probe methodology).
func Session(ctx context.Context, hosts []string, opt Options) Report {
	if len(hosts) == 0 {
		hosts = CuratedHosts()
	}
	out := Report{Results: make([]Result, 0, len(hosts))}

	controlOpen := true
	if !opt.SkipControl {
		ch := opt.ControlHost
		if ch == "" {
			ch = DefaultControlHost
		}
		if ch != "-" {
			ctrl := Target(ctx, ch, Options{
				Timeout:      opt.Timeout,
				Port:         opt.Port,
				DoH:          opt.DoH,
				Poison:       opt.Poison,
				Resolve:      opt.Resolve,
				DialTLS:      opt.DialTLS,
				LookupSystem: opt.LookupSystem,
				SkipControl:  true,
			})
			controlOpen = ctrl.Class == ClassOpen || ctrl.Class == ClassThrottleSuspect
		}
	}

	chosen := "direct"
	for _, h := range hosts {
		r := Target(ctx, h, opt)
		if !controlOpen && (r.Class == ClassIPDrop || r.Class == ClassTimeout || r.Class == ClassDPIReset) {
			// General outage - prefer timeout / desync over aggressive tunnel.
			if r.Class == ClassIPDrop {
				r.Class = ClassTimeout
				r.Path = PathFor(r.Class)
				r.Detail = strings.TrimSpace(r.Detail + "; control also down")
				r.Confidence = 0.45
			}
		} else if controlOpen && r.Class == ClassTimeout {
			// Control OK + target ambiguous → lean DPI (SNI filter common in TR).
			r.Class = ClassDPIReset
			r.Path = PathFor(r.Class)
			r.Detail = strings.TrimSpace(r.Detail + "; control open → dpi_suspect")
			r.Confidence = 0.7
		} else if controlOpen && r.Class == ClassThrottleSuspect {
			r.Confidence = 0.85
			r.Detail = strings.TrimSpace(r.Detail + "; control open → targeted throttle")
		}
		out.Results = append(out.Results, r)
		chosen = PreferPath(chosen, r.Path)
	}
	out.Chosen = chosen
	return out
}
