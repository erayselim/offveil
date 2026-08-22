//go:build windows

package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

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

// Handler dispatches one RPC method.
type Handler interface {
	Handle(method string, params map[string]any) (any, *RPCError)
}

// Server accepts named-pipe connections and serves JSON request/response.
type Server struct {
	handler Handler

	mu       sync.Mutex
	listener net.Listener
	wg       sync.WaitGroup
}

func NewServer(h Handler) *Server {
	return &Server{handler: h}
}

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

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	slog.Info("ipc: listening", "pipe", PipePath)

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return err
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.serveConn(c)
		}(conn)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.listener
	s.listener = nil
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	err := ln.Close()
	s.wg.Wait()
	return err
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("ipc: panic in connection handler", "recover", rec)
		}
	}()
	limited := io.LimitReader(conn, MaxRequestBytes)
	dec := json.NewDecoder(limited)
	enc := json.NewEncoder(conn)

	for {
		var req Request
		if err := dec.Decode(&req); err != nil {
			if err != io.EOF {
				slog.Debug("ipc: decode", "err", err)
			}
			return
		}
		resp := s.dispatch(req)
		if err := enc.Encode(resp); err != nil {
			slog.Debug("ipc: encode", "err", err)
			return
		}
	}
}

func (s *Server) dispatch(req Request) (resp Response) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("ipc: panic in dispatch", "method", req.Method, "recover", rec)
			resp = Response{
				ID: req.ID,
				OK: false,
				Error: &RPCError{
					Code:    CodeInternal,
					Message: fmt.Sprintf("internal panic: %v", rec),
				},
			}
		}
	}()
	if req.Method == "" {
		return Response{
			ID: req.ID,
			OK: false,
			Error: &RPCError{
				Code:    CodeBadRequest,
				Message: "missing method",
			},
		}
	}
	if !AllowedMethod(req.Method) {
		return Response{
			ID: req.ID,
			OK: false,
			Error: &RPCError{
				Code:    CodeBadRequest,
				Message: "unknown method: " + req.Method,
			},
		}
	}
	if n := paramsBytes(req.Params); n > MaxRequestBytes {
		return Response{
			ID: req.ID,
			OK: false,
			Error: &RPCError{
				Code:    CodeBadRequest,
				Message: "payload too large",
			},
		}
	}
	result, rpcErr := s.handler.Handle(req.Method, req.Params)
	if rpcErr != nil {
		return Response{ID: req.ID, OK: false, Error: rpcErr}
	}
	return Response{ID: req.ID, OK: true, Result: result}
}
