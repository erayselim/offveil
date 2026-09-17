package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
)

// Handler dispatches one RPC method.
type Handler interface {
	Handle(method string, params map[string]any) (any, *RPCError)
}

// Server accepts local IPC connections and serves JSON request/response.
type Server struct {
	handler Handler

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	closed   bool
	closeErr error
}

func NewServer(h Handler) *Server {
	return &Server{handler: h}
}

// Endpoint is the local IPC address (named pipe on Windows, unix socket on Darwin).
func Endpoint() string { return endpoint() }

// Close stops the listener, drops in-flight connections, and waits for them.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		err := s.closeErr
		s.mu.Unlock()
		s.wg.Wait()
		return err
	}
	s.closed = true
	ln := s.listener
	s.listener = nil
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.conns = nil
	s.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	s.wg.Wait()
	s.mu.Lock()
	s.closeErr = err
	s.mu.Unlock()
	return err
}

func (s *Server) serveListener(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	s.listener = ln
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.mu.Unlock()

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
			s.trackConn(c, true)
			defer s.trackConn(c, false)
			s.serveConn(c)
		}(conn)
	}
}

func (s *Server) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		if s.closed {
			_ = c.Close()
			return
		}
		if s.conns == nil {
			s.conns = make(map[net.Conn]struct{})
		}
		s.conns[c] = struct{}{}
		return
	}
	if s.conns != nil {
		delete(s.conns, c)
	}
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
