//go:build !windows

package dns

import "fmt"

type leakGuard struct{}

func newLeakGuard(stubHost string, tunLUID, egressLUID uint64) (*leakGuard, error) {
	return nil, fmt.Errorf("dns leak guard is Windows-only")
}

func (g *leakGuard) Apply() error  { return nil }
func (g *leakGuard) Close() error  { return nil }
