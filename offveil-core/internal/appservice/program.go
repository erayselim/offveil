package appservice

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/kardianos/service"

	"github.com/erayselim/offveil/offveil-core/internal/cleanup"
	"github.com/erayselim/offveil/offveil-core/internal/crashlog"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/engine"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
)

const (
	// Name is the service / LaunchDaemon label (Windows SCM and Darwin plist).
	Name = "offveil-core"
	// DisplayName is shown in services.msc / launchd.
	DisplayName = "offveil core"
	// Description explains the service purpose.
	Description = "offveil network protection daemon (TUN/DNS/desync/tunnel orchestration)"
)

// Program implements service.Interface.
type Program struct {
	eng    *engine.Engine
	reg    *cleanup.Registry
	server *ipc.Server
	api    *API

	cancel      context.CancelFunc
	wg          sync.WaitGroup
	stopOnce    sync.Once
	serveIPC    func(context.Context) error
	ipcReady    <-chan struct{}
	exitProcess func(int)

	// stopSCM asks the service manager to stop this process (no UAC / no sudo:
	// LocalSystem SCM stop, or root launchd unload).
	stopSCM func()
}

func NewProgram() *Program {
	reg := cleanup.NewRegistry()
	eng := engine.New(reg)
	api := &API{Eng: eng}
	p := &Program{
		eng:    eng,
		reg:    reg,
		api:    api,
		server: ipc.NewServer(api),
	}
	api.Shutdown = p.requestShutdown
	p.serveIPC, p.ipcReady, p.exitProcess = p.server.ListenAndServe, p.server.Ready(), os.Exit
	return p
}

func (p *Program) requestShutdown() {
	stop := p.stopSCM
	if stop == nil {
		// Interactive `run`: cancel IPC loop so pipe is released.
		if p.cancel != nil {
			p.cancel()
		}
		return
	}
	go func() {
		// Let the RPC response flush before SCM tears us down.
		time.Sleep(150 * time.Millisecond)
		stop()
	}()
}

func (p *Program) Start(s service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.stopSCM = func() {
		if err := s.Stop(); err != nil {
			slog.Warn("offveil-core: service stop failed", "err", err)
			// Fallback: tear down in-process so the IPC endpoint is released.
			_ = p.Stop(s)
		}
	}

	p.wg.Add(1)
	exited, accepted := make(chan error, 1), make(chan struct{})
	go func() {
		defer p.wg.Done()
		defer crashlog.Guard()
		err := p.serveIPC(ctx)
		exited <- err
		select {
		case <-accepted:
			if ctx.Err() == nil {
				slog.Error("ipc server exited unexpectedly", "err", err)
				// Teardown must run outside the listener goroutine: Stop joins it.
				go func() {
					_ = diag.RecordFailure(diag.Failure{Component: "core", Event: "ipc_unavailable", Reason: "listener_exit"})
					_ = p.Stop(s)
					p.exitProcess(1) // SCM can now apply its configured failure recovery.
				}()
			}
		case <-ctx.Done():
		}
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-p.ipcReady:
		close(accepted)
	case err := <-exited:
		cancel()
		p.wg.Wait()
		_ = diag.RecordFailure(diag.Failure{Component: "core", Event: "ipc_unavailable", Reason: "listen_failed"})
		return fmt.Errorf("IPC listener did not start: %v", err)
	case <-timer.C:
		cancel()
		_ = p.server.Close()
		p.wg.Wait()
		return fmt.Errorf("IPC listener readiness timed out")
	}
	slog.Info("offveil-core started", "service", Name)
	return nil
}

func (p *Program) Stop(s service.Service) error {
	_ = s
	p.stopOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
		slog.Info("offveil-core stopping")
		if st := p.eng.Status(); st.Protection || st.State != engine.StateStopped {
			_, _ = p.eng.Stop()
		}
		p.eng.CrashCleanup("service_stop") // docs/contracts.md §9 — leftover DNS must not blackhole
		_ = p.server.Close()
		p.wg.Wait()
		slog.Info("offveil-core stopped")
	})
	return nil
}

// NewService builds a service.Service for this program.
func NewService(p *Program) (service.Service, error) {
	svc, err := service.New(p, Config())
	if err != nil {
		return nil, fmt.Errorf("service.New: %w", err)
	}
	return svc, nil
}

// Engine exposes the engine for interactive/debug use.
func (p *Program) Engine() *engine.Engine { return p.eng }
