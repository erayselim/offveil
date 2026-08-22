//go:build !windows

package main

import (
	"context"
	"fmt"
	"net"
)

func dialPipe(ctx context.Context) (net.Conn, error) {
	return nil, fmt.Errorf("client dial is Windows-only")
}
