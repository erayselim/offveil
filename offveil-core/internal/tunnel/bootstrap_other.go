//go:build !windows && !darwin

package tunnel

import "fmt"

func bindBootstrapSocket(_ uintptr, _ string, _ int) error {
	return fmt.Errorf("physical bootstrap binding is unsupported on this platform")
}
