//go:build !darwin && !windows

package support

import "context"

func platformFacts(context.Context, map[string]any) {}
