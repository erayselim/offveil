//go:build darwin

package main

import (
	"context"
	"net"

	"github.com/erayselim/offveil/offveil-core/internal/ipc"
)

func dialPipe(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", ipc.DialPath())
}
