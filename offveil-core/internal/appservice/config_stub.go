//go:build !windows && !darwin

package appservice

import "github.com/kardianos/service"

func Config() *service.Config {
	return &service.Config{
		Name:        Name,
		DisplayName: DisplayName,
		Description: Description,
	}
}
