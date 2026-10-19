package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWARPRegistrationFailureExportsStatusWithoutResponseBody(t *testing.T) {
	client := &http.Client{Transport: warpTestTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden,
			Body:   io.NopCloser(strings.NewReader(`{"token":"private-test-token","device_id":"private-device"}`)),
			Header: make(http.Header)}, nil
	})}
	_, _, err := registerWARP(context.Background(), client)
	if err == nil || strings.Contains(err.Error(), "private") || providerFailureReason(fmt.Errorf("warp: %w", err)) != "http_403" {
		t.Fatalf("registration failure lost status or exposed response: %v", err)
	}
}

type warpTestTransport func(*http.Request) (*http.Response, error)

func (f warpTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func savedTestAccount(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := saveWARPAccount(filepath.Join(dir, "warp-account.json"), &WARPAccount{DeviceID: "test-device", PrivateKey: "test-private", AccessToken: "test-token"}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestWARPTransientFailuresPreserveAccount(t *testing.T) {
	for _, status := range []int{0, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			dir := savedTestAccount(t)
			path := filepath.Join(dir, "warp-account.json")
			before, _ := os.ReadFile(path)
			calls := 0
			client := &http.Client{Transport: warpTestTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet {
					t.Fatalf("transient error caused %s", r.Method)
				}
				if status == 0 {
					return nil, context.DeadlineExceeded
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("temporary error")), Header: make(http.Header)}, nil
			})}
			if _, _, err := loadOrRegisterWARP(context.Background(), dir, client); err == nil {
				t.Fatal("expected fetch error")
			}
			after, _ := os.ReadFile(path)
			if calls != 1 || string(before) != string(after) {
				t.Fatal("transient error changed account or retried registration")
			}
		})
	}
}

func TestWARPInvalidAccountCanRegisterAgain(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			dir := savedTestAccount(t)
			var methods []string
			client := &http.Client{Transport: warpTestTransport(func(r *http.Request) (*http.Response, error) {
				methods = append(methods, r.Method)
				code, body := http.StatusOK, `{}`
				switch r.Method {
				case http.MethodGet:
					code = status
				case http.MethodPost:
					body = `{"id":"replacement","token":"replacement-token","config":{"interface":{"addresses":{"v4":"172.16.0.2"}},"peers":[{"public_key":"test-peer","endpoint":{"host":"192.0.2.1:2408"}}]}}`
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}
			acc, profile, err := loadOrRegisterWARP(context.Background(), dir, client)
			if err != nil || acc.DeviceID != "replacement" || profile == nil || strings.Join(methods, ",") != "GET,POST,PATCH" {
				t.Fatalf("registration: %+v %+v %v %v", acc, profile, methods, err)
			}
		})
	}
}

func TestWARPRequestsShareTotalDeadline(t *testing.T) {
	dir := savedTestAccount(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	client := &http.Client{Transport: warpTestTransport(func(r *http.Request) (*http.Response, error) {
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("request has no shared deadline")
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	began := time.Now()
	if _, _, err := loadOrRegisterWARP(ctx, dir, client); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	if time.Since(began) > time.Second {
		t.Fatal("WARP exceeded shared deadline")
	}
}
