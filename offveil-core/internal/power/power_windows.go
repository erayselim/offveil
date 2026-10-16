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
	// Go callback registrations cannot be freed. Reuse one function pointer
	// and use the OS context value to identify a live subscription.
	resumeCallback = windows.NewCallback(dispatchResume)
	resumeHandlers = struct {
		sync.Mutex
		next uintptr
		live map[uintptr]func()
	}{live: make(map[uintptr]func())}
)

type deviceNotifySubscribeParams struct {
	Callback uintptr
	Context  uintptr
}

func subscribeResume(fn func()) uintptr {
	resumeHandlers.Lock()
	defer resumeHandlers.Unlock()
	resumeHandlers.next++
	id := resumeHandlers.next
	resumeHandlers.live[id] = fn
	return id
}

func unsubscribeResume(id uintptr) {
	resumeHandlers.Lock()
	delete(resumeHandlers.live, id)
	resumeHandlers.Unlock()
}

func dispatchResume(id, typ, _ uintptr) uintptr {
	if typ != pbtAPMResumeSuspend && typ != pbtAPMResumeAutomatic {
		return 0
	}
	resumeHandlers.Lock()
	fn := resumeHandlers.live[id]
	resumeHandlers.Unlock()
	if fn != nil {
		slog.Info("power: system resume", "type", typ)
		go fn()
	}
	return 0
}

func watch(ctx context.Context, onResume func()) {
	if onResume == nil {
		<-ctx.Done()
		return
	}
	id := subscribeResume(onResume)
	defer unsubscribeResume(id)
	params := &deviceNotifySubscribeParams{Callback: resumeCallback, Context: id}
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

	unsubscribeResume(id)
	if handle != 0 {
		_, _, _ = procUnreg.Call(uintptr(handle))
	}
	runtime.KeepAlive(params)
}
