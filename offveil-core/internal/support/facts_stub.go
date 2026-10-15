//go:build !darwin

package support

import "context"

func platformFacts(context.Context, map[string]any) {}
