//go:build !windows && !darwin

package main

import (
	"context"
	"fmt"
	"net"
)

func dialPipe(ctx context.Context) (net.Conn, error) {
	return nil, fmt.Errorf("client dial is Windows or Darwin only")
}
