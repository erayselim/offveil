package proc

import (
	"strings"
	"sync"
)

// TailBuffer keeps bounded process stderr without blocking the sidecar.
type TailBuffer struct {
	mu   sync.Mutex
	data []byte
}

func (b *TailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	const limit = 8192
	if len(p) >= limit {
		b.data = append(b.data[:0], p[len(p)-limit:]...)
	} else {
		if overflow := len(b.data) + len(p) - limit; overflow > 0 {
			b.data = b.data[overflow:]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}

func (b *TailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(string(b.data))
}
