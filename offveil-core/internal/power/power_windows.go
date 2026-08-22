//go:build windows

package power

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PowerRegisterSuspendResumeNotification (powrprof) delivers
// PBT_APMSUSPEND / PBT_APMRESUMESUSPEND / PBT_APMRESUMEAUTOMATIC.
// System always sends PBT_APMRESUMEAUTOMATIC on wake; user-input wake
// also sends PBT_APMRESUMESUSPEND afterward. Split-tunnel VPN routes
// often vanish after sleep on Windows 11 - rebuild on resume.

const (
	deviceNotifyCallback  = 2
	pbtAPMResumeSuspend   = 0x0007
	pbtAPMResumeAutomatic = 0x0012
)

var (
	modPowrprof = windows.NewLazySystemDLL("powrprof.dll")
	procReg     = modPowrprof.NewProc("PowerRegisterSuspendResumeNotification")
	procUnreg   = modPowrprof.NewProc("PowerUnregisterSuspendResumeNotification")
)

type deviceNotifySubscribeParams struct {
	Callback uintptr
	Context  uintptr
}

type resumeHub struct {
	mu       sync.Mutex
	onResume func()
}

func watch(ctx context.Context, onResume func()) {
	if onResume == nil {
		<-ctx.Done()
		return
	}
	hub := &resumeHub{onResume: onResume}
	cb := windows.NewCallback(func(_, typ, _ uintptr) uintptr {
		switch typ {
		case pbtAPMResumeSuspend, pbtAPMResumeAutomatic:
			hub.mu.Lock()
			fn := hub.onResume
			hub.mu.Unlock()
			if fn != nil {
				slog.Info("power: system resume", "type", typ)
				// Run off the Windows callback thread.
				go fn()
			}
		}
		return 0
	})
	params := &deviceNotifySubscribeParams{Callback: cb}
	var handle windows.Handle
	r1, _, err := procReg.Call(
		uintptr(deviceNotifyCallback),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if r1 != 0 {
		slog.Warn("power: PowerRegisterSuspendResumeNotification failed", "err", err, "code", r1)
		<-ctx.Done()
		return
	}
	slog.Info("power: suspend/resume watch registered")

	<-ctx.Done()

	hub.mu.Lock()
	hub.onResume = nil
	hub.mu.Unlock()
	if handle != 0 {
		_, _, _ = procUnreg.Call(uintptr(handle))
	}
	runtime.KeepAlive(params)
}

