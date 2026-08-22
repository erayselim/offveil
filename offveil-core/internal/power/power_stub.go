//go:build !windows

package power

import "context"

func watch(ctx context.Context, _ func()) {
	<-ctx.Done()
}
