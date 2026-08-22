package appservice

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kardianos/service"

	"github.com/erayselim/offveil/offveil-core/internal/cleanup"
	"github.com/erayselim/offveil/offveil-core/internal/crashlog"
	"github.com/erayselim/offveil/offveil-core/internal/engine"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
)

const (
	// Name is the Windows Service internal name.
	Name = "offveil-core"
	// DisplayName is shown in services.msc.
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

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// stopSCM asks Windows to stop this service (LocalSystem; no UAC).
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
			slog.Warn("offveil-core: SCM stop failed", "err", err)
			// Fallback: tear down in-process so the pipe is released.
			_ = p.Stop(s)
		}
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer crashlog.Guard()
		if err := p.server.ListenAndServe(ctx); err != nil {
			slog.Error("ipc server exited", "err", err)
		}
	}()
	slog.Info("offveil-core started", "service", Name)
	return nil
}

func (p *Program) Stop(s service.Service) error {
	_ = s
	slog.Info("offveil-core stopping")
	if st := p.eng.Status(); st.Protection || st.State != engine.StateStopped {
		_, _ = p.eng.Stop()
	}
	p.eng.CrashCleanup("service_stop")
	if p.cancel != nil {
		p.cancel()
	}
	_ = p.server.Close()
	p.wg.Wait()
	slog.Info("offveil-core stopped")
	return nil
}

// Config returns the kardianos service configuration.
// StartType=manual: UI starts the service on demand; UI quit stops it.
// End users never leave a silent daemon after closing the app.
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
