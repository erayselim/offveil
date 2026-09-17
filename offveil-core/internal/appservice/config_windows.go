//go:build windows

package appservice

import "github.com/kardianos/service"

// Config is StartType=manual: UI starts the service on demand; UI quit stops it.
func Config() *service.Config {
	return &service.Config{
		Name:        Name,
		DisplayName: DisplayName,
		Description: Description,
		Option: service.KeyValue{
			"StartType":              "manual",
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "5s",
			"OnFailureResetPeriod":   60,
		},
	}
}
