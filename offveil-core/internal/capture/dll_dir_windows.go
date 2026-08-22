//go:build windows

package capture

import (
	"golang.org/x/sys/windows"
)

func setDLLDirectory(dir string) error {
	return windows.SetDllDirectory(dir)
}
