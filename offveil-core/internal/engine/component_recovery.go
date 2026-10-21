package engine

import (
	"fmt"
	"github.com/erayselim/offveil/offveil-core/internal/capture"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/tunnel"
)

// Restart work never owns the lifecycle lock. Stop can cancel a slow provider
// or resolver restart and the late session is closed instead of being adopted.
func (e *Engine) recoverComponent(generation uint64, now time.Time) {
	e.mu.Lock()
	if !e.currentSessionLocked(generation) || e.strategySwitching {
		e.mu.Unlock()
		return
	}
	e.statusLocked()
	component, _, pid, exit := e.failedComponentLocked()
	if component == "" {
		e.mu.Unlock()
		return
	}
	key := fmt.Sprintf("%s:%d", component, pid)
	if e.failureKey != key {
		e.failureKey = key
		e.recordFailureLocked(diag.Failure{Component: component, Event: "unavailable", Exit: exit})
	}
	if e.recoveryAttempts == nil {
		e.recoveryAttempts = make(map[string]int)
	}
	attempt := e.recoveryAttempts[component]
	if attempt >= recoveryBudget {
		if attempt == recoveryBudget {
			e.recordFailureLocked(diag.Failure{Component: component, Event: "recovery_exhausted", Attempt: attempt})
			e.recoveryAttempts[component]++
		}
		e.mu.Unlock()
		return
	}
	if !e.lastRecovery.IsZero() && now.Sub(e.lastRecovery) < recoveryCooldown {
		e.mu.Unlock()
		return
	}
	if component == "desync" && (e.desyncConfig == nil || e.startDesync == nil) || component == "tunnel" && (e.tunnelConfig == nil || e.startTunnel == nil) || component == "dns" && (e.dnsConfig == nil || e.startDNS == nil) {
		e.mu.Unlock()
		return
	}
	e.recoveryAttempts[component]++
	e.lastRecovery, e.strategySwitching = now, true
	oldDes, oldTun, oldDNS := e.des, e.tun, e.dns
	captureSession, sessionCtx := e.cap, e.sessionContextLocked()
	startDes, startTun, startDNS := e.startDesync, e.startTunnel, e.startDNS
	var desCfg desync.Config
	var tunCfg tunnel.Config
	var dnsCfg offdns.Config
	if e.desyncConfig != nil {
		desCfg = *e.desyncConfig
		desCfg.ProbeHost = ""
	}
	if e.tunnelConfig != nil {
		tunCfg = *e.tunnelConfig
	}
	if e.dnsConfig != nil {
		dnsCfg = *e.dnsConfig
	}
	e.publishOperationLocked("recovery_" + component)
	e.mu.Unlock()
	var nextDes desync.Session
	var nextTun tunnel.Session
	var nextDNS offdns.Session
	var err error
	event := "restart_failed"
	switch component {
	case "desync":
		if oldDes != nil {
			err = oldDes.Close()
		}
		if err == nil {
			nextDes, err = startDes(desCfg)
		} else {
			event = "cleanup_failed"
		}
	case "tunnel":
		if oldTun != nil {
			err = oldTun.Close()
		}
		if err == nil {
			nextTun, err = startTun(tunCfg)
			if err == nil && nextTun != nil && nextTun.Info().Up && captureSession != nil {
				err = attachCaptureAdapter(sessionCtx, captureSession, capture.AdapterName)
			}
		} else {
			event = "cleanup_failed"
		}
	case "dns":
		if oldDNS != nil {
			err = oldDNS.Close()
		}
		if err == nil {
			nextDNS, err = startDNS(dnsCfg)
		} else {
			event = "cleanup_failed"
		}
	}
	if err != nil {
		if nextDes != nil {
			_ = nextDes.Close()
		}
		if nextTun != nil {
			_ = nextTun.Close()
		}
		if nextDNS != nil {
			_ = nextDNS.Close()
		}
	}
	e.mu.Lock()
	if !e.currentSessionLocked(generation) {
		e.mu.Unlock()
		if nextDes != nil {
			_ = nextDes.Close()
		}
		if nextTun != nil {
			_ = nextTun.Close()
		}
		if nextDNS != nil {
			_ = nextDNS.Close()
		}
		return
	}
	e.strategySwitching = false
	restored := false
	if err == nil {
		switch component {
		case "desync":
			if nextDes != nil {
				e.des = nextDes
				restored = nextDes.Info().Up
			}
		case "tunnel":
			if nextTun != nil {
				e.tun = nextTun
				info := nextTun.Info()
				restored = info.Up
				e.networkCheck = &NetworkHealth{Healthy: info.Healthy, CheckedAt: now.UTC().Format(time.RFC3339)}
				if info.Healthy {
					e.networkFailures = 0
				}
			}
		case "dns":
			if nextDNS != nil {
				e.dns = nextDNS
				restored = nextDNS.Info().StubUp
			}
		}
	}
	if restored {
		if component == "tunnel" && e.cap != nil {
			info := e.cap.Info()
			e.captureInfo = &info
		}
		e.failureKey = ""
		e.statusLocked()
		e.refreshNetworkStatusLocked()
		e.recordFailureLocked(diag.Failure{Component: component, Event: "recovered", Attempt: attempt + 1})
	} else {
		if event == "cleanup_failed" {
			e.recoveryAttempts[component] = recoveryBudget
		}
		e.recordFailureLocked(diag.Failure{Component: component, Event: event, Attempt: attempt + 1})
		if err == nil {
			err = fmt.Errorf("component returned no healthy session")
		}
	}
	e.publishOperationLocked("")
	e.mu.Unlock()
}
