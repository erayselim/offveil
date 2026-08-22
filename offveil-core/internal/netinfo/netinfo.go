package netinfo

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Info is the current egress / ISS snapshot used for policy cache keys.
type Info struct {
	ASN         string // e.g. "9121" or "AS9121" normalized without AS prefix when numeric
	ISPHint     string
	PublicIP    string
	Fingerprint string // local egress fingerprint; changes ⇒ invalidate
}

// Lookup discovers public IP + ASN and a local network fingerprint.
// ASN uses Team Cymru DNS (no API token). Soft-fails to asn=unknown.
func Lookup(ctx context.Context) Info {
	info := Info{
		ASN:         "unknown",
		Fingerprint: LocalFingerprint(),
	}

	pub, err := publicIP(ctx)
	if err == nil && pub != "" {
		info.PublicIP = pub
		if asn, org, aerr := cymruASN(ctx, pub); aerr == nil {
			info.ASN = asn
			info.ISPHint = org
		}
	}
	return info
}

// LocalFingerprint hashes the machine's default egress local IPs (dnscrypt-style).
// Wi-Fi ↔ Ethernet / DHCP renew that changes source IP invalidates policy cache.
func LocalFingerprint() string {
	ips := discoverLocalIPs()
	if len(ips) == 0 {
		return "offline"
	}
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	sort.Strings(parts)
	h := sha256.New()
	for _, p := range parts {
		_, _ = io.WriteString(h, p)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func discoverLocalIPs() []net.IP {
	probes := []string{"192.0.2.1:9", "[2001:db8::1]:9"}
	seen := map[string]struct{}{}
	var out []net.IP
	for _, addr := range probes {
		c, err := net.DialTimeout("udp", addr, time.Second)
		if err != nil {
			continue
		}
		la, ok := c.LocalAddr().(*net.UDPAddr)
		_ = c.Close()
		if !ok || la.IP == nil || la.IP.IsUnspecified() {
			continue
		}
		key := la.IP.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, append(net.IP(nil), la.IP...))
	}
	return out
}

func publicIP(ctx context.Context) (string, error) {
	// Multiple bootstrap sources: CF trace often fails on the same paths that
	// block DoH (diag: asn=unknown + plain_fallbacks=100%). First success wins.
	type src struct {
		url   string
		parse func(body string) string
	}
	sources := []src{
		{
			url: "https://1.1.1.1/cdn-cgi/trace",
			parse: func(body string) string {
				sc := bufio.NewScanner(strings.NewReader(body))
				for sc.Scan() {
					line := sc.Text()
					if strings.HasPrefix(line, "ip=") {
						return strings.TrimSpace(strings.TrimPrefix(line, "ip="))
					}
				}
				return ""
			},
		},
		{
			url: "https://checkip.amazonaws.com/",
			parse: func(body string) string {
				return strings.TrimSpace(body)
			},
		},
		{
			url: "https://ipv4.icanhazip.com/",
			parse: func(body string) string {
				return strings.TrimSpace(body)
			},
		},
	}

	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for _, s := range sources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("%s: HTTP %d", s.url, resp.StatusCode)
			continue
		}
		ip := s.parse(string(raw))
		if net.ParseIP(ip) != nil {
			return ip, nil
		}
		lastErr = fmt.Errorf("%s: no ip in body", s.url)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no public ip source succeeded")
	}
	return "", lastErr
}

// cymruASN queries DNS: <rev>.origin.asn.cymru.com TXT → "ASN | prefix | CC | registry | date"
func cymruASN(ctx context.Context, ipStr string) (asn, org string, err error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", "", fmt.Errorf("bad ip")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", "", fmt.Errorf("ipv6 asn skip")
	}
	name := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com.", ip4[3], ip4[2], ip4[1], ip4[0])

	type result struct {
		asn, org string
		err      error
	}
	ch := make(chan result, 1)
	go func() {
		c := new(dns.Client)
		c.Timeout = 2 * time.Second
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeTXT)
		m.RecursionDesired = true
		in, _, qerr := c.Exchange(m, "1.1.1.1:53")
		if qerr != nil {
			ch <- result{err: qerr}
			return
		}
		if in == nil || len(in.Answer) == 0 {
			ch <- result{err: fmt.Errorf("empty cymru answer")}
			return
		}
		txt, ok := in.Answer[0].(*dns.TXT)
		if !ok || len(txt.Txt) == 0 {
			ch <- result{err: fmt.Errorf("bad txt")}
			return
		}
		// "15169 | 8.8.8.0/24 | US | arin |"
		fields := strings.Split(txt.Txt[0], "|")
		a := strings.TrimSpace(fields[0])
		a = strings.TrimPrefix(strings.ToUpper(a), "AS")
		o := ""
		if len(fields) > 2 {
			o = strings.TrimSpace(fields[2]) // country as weak isp hint; AS name via separate query optional
		}
		// Optional AS name: AS15169.asn.cymru.com
		orgName := lookupASName(c, a)
		if orgName != "" {
			o = orgName
		}
		ch <- result{asn: a, org: o}
	}()

	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	case r := <-ch:
		return r.asn, r.org, r.err
	}
}

func lookupASName(c *dns.Client, asn string) string {
	if asn == "" || asn == "unknown" {
		return ""
	}
	m := new(dns.Msg)
	m.SetQuestion(fmt.Sprintf("AS%s.asn.cymru.com.", asn), dns.TypeTXT)
	in, _, err := c.Exchange(m, "1.1.1.1:53")
	if err != nil || in == nil || len(in.Answer) == 0 {
		return ""
	}
	txt, ok := in.Answer[0].(*dns.TXT)
	if !ok || len(txt.Txt) == 0 {
		return ""
	}
	// "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
	parts := strings.Split(txt.Txt[0], "|")
	if len(parts) < 5 {
		return strings.TrimSpace(txt.Txt[0])
	}
	return strings.TrimSpace(parts[4])
}

// NormalizeASN strips optional "AS" prefix for cache keys.
// Sentinel "unknown" stays lowercase so soft-fail stays distinguishable from a real ASN.
func NormalizeASN(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	upper := strings.ToUpper(s)
	if upper == "UNKNOWN" {
		return "unknown"
	}
	return strings.TrimPrefix(upper, "AS")
}
