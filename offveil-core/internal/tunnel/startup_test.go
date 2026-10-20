package tunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/proc"
)

func TestTUNStartupHelper(t *testing.T) {
	if text := os.Getenv("OFFVEIL_TUN_STARTUP_FIXTURE"); text != "" {
		fmt.Fprintln(os.Stderr, "FATAL configure tun interface:", text)
		os.Exit(1)
	}
}

func failedAdapterChild(t *testing.T, text string) (*proc.Child, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestTUNStartupHelper$")
	cmd.Env = append(os.Environ(), "OFFVEIL_TUN_STARTUP_FIXTURE="+text)
	cmd.Stderr = &proc.TailBuffer{}
	proc.PrepareCmd(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child := proc.WatchChild(cmd)
	err := proc.WaitTCP("127.0.0.1:1", time.Second, child)
	child.Close()
	return child, err
}

func TestTUNStartupRetriesOnlyTransientAdapterFailure(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		enabled    bool
		want       int
	}{
		{"adapter-release", "Cannot create a file when that file already exists.", true, 2},
		{"permission", "Access is denied.", true, 1},
		{"config", "invalid configuration", true, 1},
		{"no-tun", "Cannot create a file when that file already exists.", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			_, attempts, err := startWithTUNRetry(context.Background(), tc.enabled, func(context.Context) (*proc.Child, error) {
				calls++
				if calls == 2 {
					return nil, nil
				}
				return failedAdapterChild(t, tc.text)
			})
			if calls != tc.want || attempts != tc.want || (err == nil) != (tc.want == 2) {
				t.Fatalf("calls=%d attempts=%d err=%v", calls, attempts, err)
			}
		})
	}
}

func TestTUNStartupCancellationStopsRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, _, err := startWithTUNRetry(ctx, true, func(context.Context) (*proc.Child, error) {
		calls++
		child, err := failedAdapterChild(t, "The device is being removed")
		cancel()
		return child, err
	})
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("retry escaped canceled session: calls=%d err=%v", calls, err)
	}
}
