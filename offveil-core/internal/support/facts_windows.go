//go:build windows

package support

import (
	"context"
	"errors"
	"net"
	"unsafe"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"golang.org/x/sys/windows"
)

func platformFacts(ctx context.Context, facts map[string]any) {
	if ctx.Err() != nil {
		return
	}
	facts["windows_service"] = windowsServiceFacts()
	facts["collector_privileged"] = windows.GetCurrentProcessToken().IsElevated()
	adapter := map[string]any{"present": false}
	if nic, err := net.InterfaceByName(capture.AdapterName); err == nil {
		adapter["present"], adapter["up"], adapter["mtu"], adapter["index"] = true, nic.Flags&net.FlagUp != 0, nic.MTU, nic.Index
	}
	facts["offveil_adapter"] = adapter
}

// Query-only access works for the ordinary desktop user. No service path,
// account name, local addresses, adapter names or raw Windows errors are kept.
func windowsServiceFacts() map[string]any {
	facts := map[string]any{"state": "unknown"}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		facts["error_code"] = windowsErrorCode(err)
		return facts
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString("offveil-core")
	service, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		facts["error_code"] = windowsErrorCode(err)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			facts["state"] = "not_installed"
		}
		return facts
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var size uint32
	if err := windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &size); err != nil {
		facts["error_code"] = windowsErrorCode(err)
		return facts
	}
	facts["state"] = windowsServiceState(status.CurrentState)
	facts["pid"], facts["win32_exit_code"], facts["service_exit_code"] = status.ProcessId, status.Win32ExitCode, status.ServiceSpecificExitCode
	return facts
}

func windowsServiceState(state uint32) string {
	switch state {
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "start_pending"
	case windows.SERVICE_STOP_PENDING:
		return "stop_pending"
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_PAUSED:
		return "paused"
	default:
		return "pending"
	}
}

func windowsErrorCode(err error) uint32 {
	var code windows.Errno
	if errors.As(err, &code) {
		return uint32(code)
	}
	return 0
}
