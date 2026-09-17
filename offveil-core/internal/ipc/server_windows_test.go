//go:build windows

package ipc

import "testing"

func TestPipePath(t *testing.T) {
	if PipePath != `\\.\pipe\offveil-core` {
		t.Fatalf("PipePath=%q", PipePath)
	}
	if Endpoint() != PipePath {
		t.Fatalf("Endpoint()=%q", Endpoint())
	}
}
