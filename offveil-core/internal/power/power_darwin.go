//go:build darwin

package power

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/sys/unix"
)

const watchInterval = 2 * time.Second

func watch(ctx context.Context, onResume func()) {
	if onResume == nil {
		<-ctx.Done()
		return
	}
	slog.Info("power: sleep/wake watch registered")
	lastWake := readWakeTime()
	lastTick := time.Now()
	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			wake := readWakeTime()
			fire := NewerWake(lastWake, wake) || SleptThrough(lastTick, now, watchInterval)
			lastWake = wake
			lastTick = now
			if !fire {
				continue
			}
			slog.Info("power: system resume")
			go onResume()
		}
	}
}

func readWakeTime() time.Time {
	tv, err := unix.SysctlTimeval("kern.waketime")
	if err != nil || tv == nil {
		return time.Time{}
	}
	sec, nsec := tv.Unix()
	return time.Unix(sec, nsec)
}
