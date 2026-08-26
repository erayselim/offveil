//go:build windows

package dns

import (
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	nrptKeyPath = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	// Stable offveil NRPT rule id (not a network GUID).
	nrptRuleName = `{0FF1E110-0D05-4000-8000-00FF1E1000D5}`
	// DNS_POLICY_CONFIG_GENERIC_DNS_SERVERS
	nrptGenericDNS = 0x8
)

type nrptGuard struct {
	applied bool
}

func newNRPTGuard(stubHost string, domains []string) (*nrptGuard, error) {
	ns := NRPTNamespaces(domains)
	if len(ns) == 0 {
		return &nrptGuard{}, nil
	}
	host, _, err := splitHostPortDefault(stubHost, "53")
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "127.0.0.1"
	}

	root, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptKeyPath, registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		// Parent may not exist on some SKUs.
		if err2 := createNRPTRoot(); err2 != nil {
			return nil, fmt.Errorf("nrpt root: %w", err)
		}
		root, err = registry.OpenKey(registry.LOCAL_MACHINE, nrptKeyPath, registry.CREATE_SUB_KEY|registry.SET_VALUE)
		if err != nil {
			return nil, fmt.Errorf("nrpt root: %w", err)
		}
	}
	_ = root.Close()

	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptKeyPath+`\`+nrptRuleName, registry.SET_VALUE)
	if err != nil {
		return nil, fmt.Errorf("nrpt create: %w", err)
	}
	defer key.Close()

	if err := key.SetDWordValue("Version", 2); err != nil {
		return nil, err
	}
	if err := key.SetDWordValue("ConfigOptions", nrptGenericDNS); err != nil {
		return nil, err
	}
	if err := key.SetStringsValue("Name", ns); err != nil {
		return nil, err
	}
	if err := key.SetStringValue("GenericDNSServers", host); err != nil {
		return nil, err
	}

	reloadDNSClient()
	slog.Info("dns: NRPT applied", "namespaces", len(ns), "stub", host)
	return &nrptGuard{applied: true}, nil
}

func createNRPTRoot() error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	return k.Close()
}

func (g *nrptGuard) Close() error {
	if g == nil || !g.applied {
		return nil
	}
	g.applied = false
	return RemoveNRPT()
}

// NRPTPresent is true when our Name Resolution Policy rule is in the registry.
func NRPTPresent() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptKeyPath+`\`+nrptRuleName, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

// RemoveNRPT deletes the offveil NRPT rule. Missing is OK.
func RemoveNRPT() error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptKeyPath+`\`+nrptRuleName)
	reloadDNSClient()
	if err != nil && !isNotFound(err) {
		return err
	}
	if err == nil {
		slog.Info("dns: NRPT removed")
	}
	return nil
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if err == registry.ErrNotExist {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "cannot find")
}

const (
	// SERVICE_CONTROL_PARAMCHANGE — DnsCache reloads DnsPolicyConfig from the registry.
	serviceControlParamChange = 6
)

var (
	moddnsapi              = windows.NewLazySystemDLL("dnsapi.dll")
	procFlushResolverCache = moddnsapi.NewProc("DnsFlushResolverCache")
)

// reloadDNSClient pushes NRPT registry changes into DnsCache memory, then flushes answers.
func reloadDNSClient() {
	notifyDNSClientReload()
	FlushResolverCache()
}

func notifyDNSClientReload() {
	name, err := windows.UTF16PtrFromString("DnsCache")
	if err != nil {
		return
	}
	mgr, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		slog.Debug("dns: OpenSCManager", "err", err)
		return
	}
	defer windows.CloseServiceHandle(mgr)

	svc, err := windows.OpenService(mgr, name, windows.SERVICE_PAUSE_CONTINUE)
	if err != nil {
		slog.Debug("dns: OpenService DnsCache", "err", err)
		return
	}
	defer windows.CloseServiceHandle(svc)

	var status windows.SERVICE_STATUS
	if err := windows.ControlService(svc, serviceControlParamChange, &status); err != nil {
		slog.Debug("dns: DnsCache PARAMCHANGE", "err", err)
	}
}

// FlushResolverCache clears the Windows DNS client cache (ipconfig /flushdns).
func FlushResolverCache() {
	if procFlushResolverCache.Find() != nil {
		return
	}
	_, _, _ = procFlushResolverCache.Call()
}
