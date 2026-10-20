package tunnel

import (
	"context"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/proc"
)

// All attempts share one readiness budget. Only known transient adapter errors
// are retried; auth, configuration, permission and network errors are not.
func startWithTUNRetry(ctx context.Context, enabled bool, launch func(context.Context) (*proc.Child, error)) (*proc.Child, int, error) {
	startup, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var lastChild *proc.Child
	for attempt := 1; ; attempt++ {
		if err := startup.Err(); err != nil {
			return lastChild, attempt - 1, err
		}
		child, err := launch(startup)
		lastChild = child
		if err == nil {
			if startup.Err() != nil {
				child.Close()
				return child, attempt, startup.Err()
			}
			return child, attempt, nil
		}
		if child != nil {
			child.Close()
		}
		var reason string
		if exit := child.Exit(); exit != nil {
			reason = exit.Reason
		}
		transient := reason == "adapter_exists" || reason == "adapter_removing" || reason == "adapter_busy"
		if !enabled || !transient || attempt >= 3 {
			return child, attempt, err
		}
		timer := time.NewTimer(time.Duration(attempt) * 250 * time.Millisecond)
		select {
		case <-startup.Done():
			timer.Stop()
			return child, attempt, startup.Err()
		case <-timer.C:
		}
	}
}
