//go:build !windows

package dns

type nrptGuard struct{ applied bool }

func newNRPTGuard(string, []string) (*nrptGuard, error) { return &nrptGuard{}, nil }

func (g *nrptGuard) Close() error { return nil }

func NRPTPresent() bool   { return false }
func RemoveNRPT() error   { return nil }
func FlushResolverCache() {}

func reloadDNSClient() {}
