//go:build !windows

package ipc

import (
	"context"
	"fmt"
)

const PipePath = "offveil-core.sock"

type Handler interface {
	Handle(method string, params map[string]any) (any, *RPCError)
}

type Server struct {
	handler Handler
}

func NewServer(h Handler) *Server {
	return &Server{handler: h}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	return fmt.Errorf("named pipe IPC is Windows-only")
}

func (s *Server) Close() error { return nil }
