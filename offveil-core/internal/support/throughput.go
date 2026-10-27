package support

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

// throughputURL serves a fixed-size body with no account or cookie.
const (
	throughputURL   = "https://speed.cloudflare.com/__down?bytes=4000000"
	throughputBytes = 4_000_000
	throughputLimit = 12 * time.Second
)

// ThroughputSample compares the current route with the physical interface.
// Only sizes, durations and an error class are recorded.
type ThroughputSample struct {
	Route      string  `json:"route"`
	Bytes      int64   `json:"bytes"`
	Millis     int64   `json:"ms"`
	Mbps       float64 `json:"mbps"`
	ErrorClass string  `json:"error_class,omitempty"`
}

// Throughput downloads a small fixed body once over the current OS route and,
// when egress is known, once bound to the physical interface.
func Throughput(ctx context.Context, egress string) []ThroughputSample {
	out := []ThroughputSample{sample(ctx, "current", &net.Dialer{Timeout: 5 * time.Second})}
	if egress != "" {
		out = append(out, sample(ctx, "physical", tunnel.PhysicalDialer(egress, 5*time.Second)))
	}
	return out
}

// EgressName reads the physical interface from a live daemon report.
func EgressName(in diag.Input) string {
	capture, _ := in.Sidecars["capture"].(map[string]any)
	egress, _ := capture["egress"].(map[string]any)
	name, _ := egress["name"].(string)
	return name
}

func sample(parent context.Context, route string, dialer *net.Dialer) ThroughputSample {
	result := ThroughputSample{Route: route}
	ctx, cancel := context.WithTimeout(parent, throughputLimit)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, throughputURL, nil)
	if err != nil {
		result.ErrorClass = "request"
		return result
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		result.ErrorClass = networkErrorClass(err)
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		result.ErrorClass = "http_status"
		return result
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, throughputBytes))
	elapsed := time.Since(start)
	result.Bytes, result.Millis = n, elapsed.Milliseconds()
	if elapsed > 0 {
		result.Mbps = float64(int(float64(n)*8/elapsed.Seconds()/1e4)) / 100
	}
	if err != nil {
		result.ErrorClass = networkErrorClass(err)
	}
	return result
}
