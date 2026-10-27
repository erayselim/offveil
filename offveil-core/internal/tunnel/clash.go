package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// clashControl is sing-box's loopback selector API. The secret is per process
// and never leaves memory; other local users cannot switch group paths.
type clashControl struct {
	addr   string
	secret string
}

func newClashControl() (*clashControl, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("selector port: %w", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return &clashControl{addr: addr, secret: hex.EncodeToString(b[:])}, nil
}

func (c *clashControl) address() string {
	if c == nil {
		return ""
	}
	return c.addr
}

func (c *clashControl) token() string {
	if c == nil {
		return ""
	}
	return c.secret
}

var clashHTTP = &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}

// selectOutbound switches one selector and reads it back.
func (c *clashControl) selectOutbound(ctx context.Context, selector, outbound string) error {
	if c == nil {
		return fmt.Errorf("selector control unavailable")
	}
	endpoint := "http://" + c.addr + "/proxies/" + url.PathEscape(selector)
	body, _ := json.Marshal(map[string]string{"name": outbound})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := clashHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("selector %s: %w", selector, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("selector %s: HTTP %d", selector, resp.StatusCode)
	}
	now, err := c.current(ctx, selector)
	if err != nil {
		return err
	}
	if now != outbound {
		return fmt.Errorf("selector %s stayed on %s", selector, now)
	}
	return nil
}

func (c *clashControl) current(ctx context.Context, selector string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+c.addr+"/proxies/"+url.PathEscape(selector), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	resp, err := clashHTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("selector %s: %w", selector, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("selector %s: HTTP %d", selector, resp.StatusCode)
	}
	var out struct {
		Now string `json:"now"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return "", err
	}
	return out.Now, nil
}
