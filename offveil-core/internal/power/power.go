// Package power watches system suspend/resume so split-tunnel routes can be rebuilt after wake.
package power

import "context"

// Watch registers for power events until ctx is cancelled.
// onResume is invoked after the system wakes (sleep/hibernate).
// Windows: PowerRegisterSuspendResumeNotification.
// Darwin: kern.waketime + freeze-gap (no CGO / IOKit).
// Other OS: wait until ctx is done.
func Watch(ctx context.Context, onResume func()) {
	watch(ctx, onResume)
}
