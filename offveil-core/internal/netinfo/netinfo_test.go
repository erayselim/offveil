package netinfo_test

import (
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/netinfo"
)

func TestNormalizeASN(t *testing.T) {
	cases := map[string]string{
		"":        "unknown",
		"unknown": "unknown",
		"UNKNOWN": "unknown",
		"AS9121":  "9121",
		"as9121":  "9121",
		"9121":    "9121",
	}
	for in, want := range cases {
		if got := netinfo.NormalizeASN(in); got != want {
			t.Fatalf("%q → %q want %q", in, got, want)
		}
	}
}

func TestLocalFingerprintStable(t *testing.T) {
	a := netinfo.LocalFingerprint()
	b := netinfo.LocalFingerprint()
	if a == "" || a != b {
		t.Fatalf("%q vs %q", a, b)
	}
}
