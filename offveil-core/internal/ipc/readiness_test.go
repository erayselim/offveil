package ipc

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type readinessListener struct {
	closed chan struct{}
	once   sync.Once
}

func (l *readinessListener) Accept() (net.Conn, error) { <-l.closed; return nil, net.ErrClosed }
func (l *readinessListener) Close() error              { l.once.Do(func() { close(l.closed) }); return nil }
func (l *readinessListener) Addr() net.Addr            { return &net.UnixAddr{Name: "fixture", Net: "unix"} }

func TestIPCReadyMeansBoundListenerAndCloseReleasesIt(t *testing.T) {
	s := NewServer(pingHandler{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &readinessListener{closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.serveListener(ctx, l) }()
	select {
	case <-s.Ready():
	case <-time.After(time.Second):
		t.Fatal("listener readiness not published")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("exit=%v", err)
	}
}

func TestClosedIPCServerRejectsLateListener(t *testing.T) {
	s := NewServer(pingHandler{})
	_ = s.Close()
	l := &readinessListener{closed: make(chan struct{})}
	if err := s.serveListener(context.Background(), l); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("exit=%v", err)
	}
	select {
	case <-l.closed:
	default:
		t.Fatal("late listener leaked")
	}
	select {
	case <-s.Ready():
		t.Fatal("closed server reported ready")
	default:
	}
}
