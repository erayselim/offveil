//go:build darwin

package dns

import (
	"os/exec"
	"strings"
)

type netsetupCtl struct{}

func liveSystemDNS() systemDNS { return netsetupCtl{} }

func (netsetupCtl) ListServices() ([]hwService, error) {
	out, err := runNetsetup(listOrderArgs()...)
	if err == nil && strings.TrimSpace(out) != "" {
		if parsed := parseListNetworkServiceOrder(out); len(parsed) > 0 {
			return parsed, nil
		}
	}
	out, err = runNetsetup(listAllArgs()...)
	if err != nil {
		return nil, err
	}
	return parseListAllNetworkServices(out), nil
}

func (netsetupCtl) GetDNS(name string) ([]string, bool, error) {
	out, err := runNetsetup(getDNSArgs(name)...)
	servers, dhcp := parseGetDNSServers(out)
	if err != nil && len(servers) == 0 {
		return nil, true, err
	}
	return servers, dhcp, nil
}

func (netsetupCtl) SetDNS(name string, servers []string) error {
	_, err := runNetsetup(setDNSArgs(name, servers)...)
	return err
}

func (netsetupCtl) Flush() error {
	return runKillallHUP()
}

var runNetsetup = func(args ...string) (string, error) {
	cmd := exec.Command(networksetupBin, args...)
	b, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

var runKillallHUP = func() error {
	cmd := exec.Command(killallBin, flushResolverArgs()...)
	return cmd.Run()
}
