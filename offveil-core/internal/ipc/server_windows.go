//go:build windows

package ipc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Microsoft/go-winio"
)

// PipePath is the local-only named pipe (docs/contracts.md §2).
const PipePath = `\\.\pipe\offveil-core`

// pipeSDDL: Protected DACL - LocalSystem full control, Authenticated Users
// read/write (interactive UI). No Everyone / Anonymous. go-winio also sets
// FILE_PIPE_REJECT_REMOTE_CLIENTS so remote SMB clients cannot connect.
//
// Ref: Microsoft named-pipe security; Tailscale safesocket pattern (BU+SY).
const pipeSDDL = "D:P(A;;FA;;;SY)(A;;GRGW;;;AU)"

func endpoint() string { return PipePath }

// ListenAndServe opens the pipe and serves until ctx is cancelled or Close.
func (s *Server) ListenAndServe(ctx context.Context) error {
	cfg := &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	}
	ln, err := winio.ListenPipe(PipePath, cfg)
	if err != nil {
		return fmt.Errorf("listen %s: %w", PipePath, err)
	}
	slog.Info("ipc: listening", "pipe", PipePath)
	return s.serveListener(ctx, ln)
}
