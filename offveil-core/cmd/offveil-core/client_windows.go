//go:build windows

package main

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"

	"github.com/erayselim/offveil/offveil-core/internal/ipc"
)

func dialPipe(ctx context.Context) (net.Conn, error) {
	return winio.DialPipeContext(ctx, ipc.PipePath)
}
