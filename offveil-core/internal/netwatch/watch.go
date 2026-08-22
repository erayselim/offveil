// Package netwatch detects local egress changes (Wi-Fi ↔ Ethernet / DHCP).
// Policy keys on LocalFingerprint; a change must invalidate the cache and
// re-probe. Polling the fingerprint is simpler than NotifyAddrChange
// callbacks and still catches interface flips within a few seconds.
package netwatch

import (
	"context"
	"log/slog"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
)

const (
	// DefaultInterval is how often we sample LocalFingerprint while protection is up.
	DefaultInterval = 5 * time.Second
)

// Debounce waits after the first mismatch so Wi-Fi flaps settle.
// Overridable in tests.
var Debounce = 2 * time.Second

// FingerprintFunc returns the current local egress fingerprint (overridable in tests).
type FingerprintFunc func() string

// Start polls the local fingerprint until ctx is cancelled.
// onChange is called with (previous, next) after Debounce when the value changes
// and remains different (skips offline↔offline noise).
func Start(ctx context.Context, interval time.Duration, fp FingerprintFunc, onChange func(prev, next string)) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if fp == nil {
		fp = netinfo.LocalFingerprint
	}
	go run(ctx, interval, fp, onChange)
}

func run(ctx context.Context, interval time.Duration, fp FingerprintFunc, onChange func(prev, next string)) {
	prev := fp()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			next := fp()
			if next == prev || next == "" || next == "offline" {
				if next != "" && next != "offline" {
					prev = next
				}
				continue
			}
			// Candidate change - debounce then re-sample.
			candidate := next
			timer := time.NewTimer(Debounce)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			stable := fp()
			if stable == "" || stable == "offline" || stable == prev || stable != candidate {
				if stable != "" && stable != "offline" {
					prev = stable
				}
				continue
			}
			slog.Info("netwatch: egress fingerprint changed", "from", prev, "to", stable)
			if onChange != nil {
				onChange(prev, stable)
			}
			prev = stable
		}
	}
}
