//go:build darwin

package appservice

import "github.com/kardianos/service"

// Config is demand-start LaunchDaemon: KeepAlive=false, RunAtLoad=false.
// Boot loads the plist but does not start the process. UI load+start;
// UI shutdown unloads. kardianos default KeepAlive=true would ignore Stop
// (kardianos/service#285).
func Config() *service.Config {
	cfg := &service.Config{
		Name:        Name,
		DisplayName: DisplayName,
		Description: Description,
		Executable:  CanonicalBinary(),
		Option:      DarwinLaunchdOptions(),
	}
	return cfg
}
