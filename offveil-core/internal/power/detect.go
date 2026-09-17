package power

import "time"

// SleptThrough is true when the process was frozen (or the clock jumped)
// longer than a couple of watch intervals — typical after system sleep.
func SleptThrough(prev, now time.Time, interval time.Duration) bool {
	if prev.IsZero() || now.IsZero() || interval <= 0 {
		return false
	}
	return now.Sub(prev) > interval*2+3*time.Second
}

// NewerWake is true when kern.waketime advanced (Darwin sysctl).
func NewerWake(prev, next time.Time) bool {
	return !prev.IsZero() && !next.IsZero() && next.After(prev)
}
