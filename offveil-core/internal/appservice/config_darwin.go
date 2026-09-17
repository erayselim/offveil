//go:build darwin

package appservice

import (
	"os"

	"github.com/kardianos/service"
)

// Config is demand-start LaunchDaemon: KeepAlive=false, RunAtLoad=false.
// Boot loads the plist but does not start the process. UI load+start;
// UI shutdown unloads. kardianos default KeepAlive=true would ignore Stop
// (kardianos/service#285).
func Config() *service.Config {
	cfg := &service.Config{
		Name:        Name,
		DisplayName: DisplayName,
		Description: Description,
		Option:      DarwinLaunchdOptions(),
	}
	if p := CanonicalBinary(); fileExists(p) {
		cfg.Executable = p
	}
	return cfg
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
