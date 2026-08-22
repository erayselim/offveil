// Package power watches system suspend/resume so split-tunnel routes can be rebuilt after wake.
package power

import "context"

// Watch registers for power events until ctx is cancelled.
// onResume is invoked after the system wakes (sleep/hibernate).
// Non-Windows builds are a no-op.
func Watch(ctx context.Context, onResume func()) {
	watch(ctx, onResume)
}
