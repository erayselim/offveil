package dns

import (
	"fmt"
	"net"
	"strings"
)

// Darwin system DNS uses networksetup on hardware services (Wi-Fi, Ethernet,
// Thunderbolt). It does not write /etc/resolver/ — that directory is a
// per-TLD overlay (macOS 26 mDNS/custom-TLD trap). Catch-all "." is a
// Windows NRPT namespace, not an /etc/resolver file.

const (
	networksetupBin = "/usr/sbin/networksetup"
	killallBin      = "/usr/bin/killall"
	emptyDNSToken   = "empty"
	stubDNSIP       = "127.0.0.1"
)

// resolverOverlayDir is the path we must never create or write.
const resolverOverlayDir = "/etc/resolver"

type hwService struct {
	Name         string
	HardwarePort string
	Device       string
	Disabled     bool
}

// systemDNS is the Darwin steering surface. Tests fake it; Darwin wraps networksetup.
type systemDNS interface {
	ListServices() ([]hwService, error)
	GetDNS(name string) (servers []string, dhcp bool, err error)
	SetDNS(name string, servers []string) error
	Flush() error
}

func skipNetworkService(name, hardwarePort, device string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	hp := strings.ToLower(strings.TrimSpace(hardwarePort))
	dev := strings.ToLower(strings.TrimSpace(device))
	blob := n + " " + hp

	if dev != "" {
		for _, p := range []string{"utun", "ipsec", "ppp", "gif", "stf", "awdl", "llw", "bridge"} {
			if strings.HasPrefix(dev, p) {
				return "virtual:" + device
			}
		}
	}
	if strings.Contains(blob, "thunderbolt bridge") {
		return "bridge"
	}
	if strings.Contains(blob, "bluetooth") {
		return "bluetooth"
	}
	for _, k := range vpnServiceTokens {
		if strings.Contains(blob, k) || strings.Contains(dev, k) {
			return "vpn:" + name
		}
	}
	return ""
}

var vpnServiceTokens = []string{
	"vpn", "utun", "ipsec", "l2tp", "pptp", "ikev2", "anyconnect",
	"tailscale", "wireguard", "openvpn", "proton", "mullvad", "nordvpn",
	"warp", "zerotier", "hamachi", "tunnelblick", "viscosity", "cisco",
}

func filterDNSTargets(in []hwService) []hwService {
	var out []hwService
	for _, s := range in {
		if s.Disabled || strings.TrimSpace(s.Name) == "" {
			continue
		}
		if reason := skipNetworkService(s.Name, s.HardwarePort, s.Device); reason != "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func parseListAllNetworkServices(out string) []hwService {
	var services []hwService
	for i, line := range splitLines(out) {
		if i == 0 && (strings.Contains(strings.ToLower(line), "asterisk") || strings.Contains(strings.ToLower(line), "denotes")) {
			continue
		}
		if line == "" {
			continue
		}
		disabled := false
		if strings.HasPrefix(line, "*") {
			disabled = true
			line = strings.TrimSpace(strings.TrimPrefix(line, "*"))
		}
		if line == "" {
			continue
		}
		services = append(services, hwService{Name: line, Disabled: disabled})
	}
	return services
}

func parseListNetworkServiceOrder(out string) []hwService {
	var services []hwService
	var cur *hwService
	flush := func() {
		if cur == nil {
			return
		}
		services = append(services, *cur)
		cur = nil
	}
	for _, line := range splitLines(out) {
		low := strings.ToLower(line)
		if strings.Contains(low, "asterisk") && strings.Contains(low, "denotes") {
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "(Hardware Port:") || strings.HasPrefix(line, "(hardware port:") {
			port, dev := parseHardwarePortLine(line)
			if cur != nil {
				cur.HardwarePort = port
				cur.Device = dev
			}
			continue
		}
		name, disabled, ok := parseServiceOrderName(line)
		if !ok {
			continue
		}
		flush()
		cur = &hwService{Name: name, Disabled: disabled}
	}
	flush()
	return services
}

func parseServiceOrderName(line string) (name string, disabled bool, ok bool) {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "*") {
		disabled = true
		s = strings.TrimSpace(strings.TrimPrefix(s, "*"))
	}
	if !strings.HasPrefix(s, "(") {
		return "", false, false
	}
	close := strings.Index(s, ")")
	if close < 0 {
		return "", false, false
	}
	name = strings.TrimSpace(s[close+1:])
	if name == "" {
		return "", false, false
	}
	return name, disabled, true
}

func parseHardwarePortLine(line string) (port, device string) {
	s := strings.TrimSpace(line)
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(s, ")")
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		low := strings.ToLower(p)
		switch {
		case strings.HasPrefix(low, "hardware port:"):
			port = strings.TrimSpace(p[len("Hardware Port:"):])
			if i := strings.Index(low, ":"); i >= 0 {
				port = strings.TrimSpace(p[i+1:])
			}
		case strings.HasPrefix(low, "device:"):
			if i := strings.Index(p, ":"); i >= 0 {
				device = strings.TrimSpace(p[i+1:])
			}
		}
	}
	return port, device
}

func parseGetDNSServers(out string) (servers []string, dhcp bool) {
	s := strings.TrimSpace(out)
	if s == "" {
		return nil, true
	}
	low := strings.ToLower(s)
	if strings.Contains(low, "aren't any dns") || strings.Contains(low, "are not any dns") {
		return nil, true
	}
	if strings.Contains(low, "error:") {
		return nil, true
	}
	for _, line := range splitLines(s) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			servers = append(servers, ip.String())
		}
	}
	if len(servers) == 0 {
		return nil, true
	}
	return servers, false
}

func setDNSArgs(service string, servers []string) []string {
	if len(servers) == 0 {
		return []string{"-setdnsservers", service, emptyDNSToken}
	}
	return append([]string{"-setdnsservers", service}, servers...)
}

func getDNSArgs(service string) []string {
	return []string{"-getdnsservers", service}
}

func listOrderArgs() []string { return []string{"-listnetworkserviceorder"} }

func listAllArgs() []string { return []string{"-listallnetworkservices"} }

func flushResolverArgs() []string { return []string{"-HUP", "mDNSResponder"} }

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

func onlyLoopbackStub(servers []string) bool {
	n := 0
	for _, s := range servers {
		ip := net.ParseIP(s)
		if ip == nil {
			return false
		}
		if !ip.IsLoopback() {
			return false
		}
		n++
	}
	return n > 0
}

// applySystemDNSWith snapshots current DNS, then points targets at stubIP.
func applySystemDNSWith(ctl systemDNS, stubIP string) error {
	if stubIP == "" {
		stubIP = stubDNSIP
	}
	if net.ParseIP(stubIP) == nil {
		return fmt.Errorf("dns: invalid stub ip %q", stubIP)
	}
	all, err := ctl.ListServices()
	if err != nil {
		return err
	}
	targets := filterDNSTargets(all)
	if len(targets) == 0 {
		return fmt.Errorf("dns: no networksetup services to steer")
	}
	snap := RestoreSnapshot{StubIP: stubIP}
	for _, svc := range targets {
		servers, dhcp, gerr := ctl.GetDNS(svc.Name)
		if gerr != nil {
			dhcp = true
			servers = nil
		}
		snap.Services = append(snap.Services, ServiceDNS{
			Name: svc.Name,
			DNS:  append([]string{}, servers...),
			DHCP: dhcp || len(servers) == 0,
		})
	}
	if err := SaveRestoreSnapshot(snap); err != nil {
		return fmt.Errorf("dns: snapshot: %w", err)
	}

	applied := 0
	var first error
	for _, svc := range snap.Services {
		if err := ctl.SetDNS(svc.Name, []string{stubIP}); err != nil {
			if first == nil {
				first = fmt.Errorf("%s: %w", svc.Name, err)
			}
			continue
		}
		applied++
	}
	if applied == 0 {
		_, _ = restoreSystemDNSWith(ctl, true, false)
		if first == nil {
			first = fmt.Errorf("dns: setdnsservers failed on all services")
		}
		return first
	}
	_ = ctl.Flush()
	return nil
}

// restoreSystemDNSWith writes snapshot DNS (or empty) back onto services.
func restoreSystemDNSWith(ctl systemDNS, armed, stubUp bool) (detail string, err error) {
	snap, loadErr := LoadRestoreSnapshot()
	if loadErr != nil {
		return "", fmt.Errorf("load snapshot: %w", loadErr)
	}
	restored := 0
	var first error
	if snap != nil {
		armed = true
		for _, svc := range snap.Services {
			servers := svc.DNS
			if svc.DHCP {
				servers = nil
			}
			if e := ctl.SetDNS(svc.Name, servers); e != nil {
				if first == nil {
					first = e
				}
				continue
			}
			restored++
		}
		_ = ClearRestoreSnapshot()
	}

	flushed := 0
	if !stubUp || armed {
		n, ferr := flushLeftoverStubDNS(ctl, armed, stubUp)
		flushed = n
		if ferr != nil && first == nil {
			first = ferr
		}
	}
	_ = ctl.Flush()

	switch {
	case restored > 0 && flushed > 0:
		detail = fmt.Sprintf("restored %d, flushed %d", restored, flushed)
	case restored > 0:
		detail = fmt.Sprintf("restored %d", restored)
	case flushed > 0:
		detail = fmt.Sprintf("flushed %d", flushed)
	default:
		detail = "clean"
	}
	return detail, first
}

func flushLeftoverStubDNS(ctl systemDNS, armed, stubUp bool) (int, error) {
	if !armed && stubUp {
		return 0, nil
	}
	all, err := ctl.ListServices()
	if err != nil {
		return 0, err
	}
	flushed := 0
	var first error
	for _, svc := range filterDNSTargets(all) {
		servers, dhcp, gerr := ctl.GetDNS(svc.Name)
		if gerr != nil || dhcp {
			continue
		}
		if !onlyLoopbackStub(servers) {
			continue
		}
		if err := ctl.SetDNS(svc.Name, nil); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		flushed++
	}
	return flushed, first
}

func leftoverStubPresent(ctl systemDNS) bool {
	snap, err := LoadRestoreSnapshot()
	if err == nil && snap != nil && len(snap.Services) > 0 {
		return true
	}
	all, err := ctl.ListServices()
	if err != nil {
		return false
	}
	for _, svc := range filterDNSTargets(all) {
		servers, dhcp, gerr := ctl.GetDNS(svc.Name)
		if gerr != nil || dhcp {
			continue
		}
		if onlyLoopbackStub(servers) {
			return true
		}
	}
	return false
}

func usesResolverOverlay(args []string) bool {
	joined := strings.Join(args, " ")
	return strings.Contains(joined, resolverOverlayDir)
}
