package dns

import (
	"net"
	"time"
)

func localResolverListening() bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:53", 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
