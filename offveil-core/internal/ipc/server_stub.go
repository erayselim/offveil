//go:build !windows && !darwin

package ipc

import (
	"context"
	"fmt"
)

const PipePath = "offveil-core.sock"

func endpoint() string { return PipePath }

func (s *Server) ListenAndServe(ctx context.Context) error {
	_ = ctx
	return fmt.Errorf("IPC is Windows or Darwin only")
}
