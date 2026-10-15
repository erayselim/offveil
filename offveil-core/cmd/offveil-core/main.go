package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/kardianos/service"

	"github.com/erayselim/offveil/offveil-core/internal/appservice"
	"github.com/erayselim/offveil/offveil-core/internal/crashlog"
	"github.com/erayselim/offveil/offveil-core/internal/desync"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/repair"
	"github.com/erayselim/offveil/offveil-core/internal/sidecar"
	"github.com/erayselim/offveil/offveil-core/internal/support"
	"github.com/erayselim/offveil/offveil-core/internal/version"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if len(os.Args) < 2 {
		if runtime.GOOS == "darwin" && os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "The system daemon must be started by launchd after setup. To save a support ZIP without installation, run: offveil-core support")
			os.Exit(1)
		}
		if err := runService(); err != nil {
			slog.Error("service run failed", "err", err)
			os.Exit(1)
		}
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "run":
		if err := runInteractive(); err != nil {
			slog.Error("run failed", "err", err)
			os.Exit(1)
		}
	case "install":
		mustServiceControl("install")
	case "uninstall":
		leftoverNetworkCleanup()
		mustServiceControl("uninstall")
	case "repair":
		printRepair(repair.Run())
	case "start":
		mustServiceControl("start")
	case "stop":
		mustServiceControl("stop")
	case "setup":
		// First-run from UI: install (if needed) + start in one elevated process.
		mustSetup()
	case "status":
		printServiceStatus()
	case "client":
		clientFlags := flag.NewFlagSet("client", flag.ExitOnError)
		method := clientFlags.String("method", "ping", "RPC method")
		timeout := clientFlags.Duration("timeout", 25*time.Second, "RPC deadline")
		_ = clientFlags.Parse(os.Args[2:])
		if *timeout <= 0 || *timeout > 3*time.Minute {
			fmt.Fprintln(os.Stderr, "client: timeout must be between 0 and 3 minutes")
			os.Exit(1)
		}
		if err := runClientWithTimeout(*method, *timeout); err != nil {
			fmt.Fprintf(os.Stderr, "client: %v\n", err)
			os.Exit(1)
		}
	case "support":
		supportFlags := flag.NewFlagSet("support", flag.ExitOnError)
		output := supportFlags.String("output", "", "ZIP destination (default: Downloads)")
		uiError := supportFlags.String("ui-error", "", "last UI operation error")
		_ = supportFlags.Parse(os.Args[2:])
		fmt.Fprintln(os.Stderr, "Collecting support information; a stopped or unreachable daemon is supported.")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		in := support.Collect(ctx, requestRPC)
		if *uiError != "" {
			if len(*uiError) > 4096 {
				*uiError = (*uiError)[:4096]
			}
			in.System["last_ui_error"] = support.RedactLocalError(*uiError)
		}
		cancel()
		meta, err := support.Write(in, *output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "support: %v\n", err)
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(meta); err != nil {
			os.Exit(1)
		}
	case "check-payload":
		binary, err := sidecar.Locate(sidecar.ByeDPI)
		if err == nil {
			err = desync.ValidateNativeArguments(context.Background(), binary)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "payload: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("All native ByeDPI strategies were accepted by the bundled binary.")
	case "version", "-version", "--version":
		fmt.Printf("offveil-core %s (contracts %d)\n", version.Version, version.ContractsVersion)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printHelp()
		os.Exit(2)
	}
}

func printHelp() {
	fmt.Fprintf(os.Stderr, `offveil-core - offveil protection daemon

Usage:
  offveil-core                 Run as service (Windows SCM / Darwin launchd)
  offveil-core run             Interactive foreground (dev)
  offveil-core install         Install service "offveil-core"
  offveil-core uninstall       Remove leftover DNS/network state, then the service
  offveil-core repair          Restore leftover DNS/network/adapter (no IPC; stop-fail safe)
  offveil-core setup           Install (if needed) + start - single elevation for UI
  offveil-core start|stop      Control installed service
  offveil-core status          Query service status
  offveil-core client -method ping|status|start|stop|restart|health|test|repair
  offveil-core support [-output /path/to/support.zip]  Save a ZIP without requiring the daemon
  offveil-core check-payload   Validate native strategy arguments with the bundled sidecar
  offveil-core version

IPC: %s
`, ipc.Endpoint())
}

func runService() error {
	defer crashlog.Guard()
	p := appservice.NewProgram()
	svc, err := appservice.NewService(p)
	if err != nil {
		return err
	}
	return svc.Run()
}

func runInteractive() error {
	p := appservice.NewProgram()
	svc, err := appservice.NewService(p)
	if err != nil {
		return err
	}

	if err := p.Start(svc); err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	sig := <-sigCh
	slog.Info("signal received", "sig", sig.String())
	return p.Stop(svc)
}

func leftoverNetworkCleanup() {
	printRepair(repair.LeftoverNetwork())
}

func printRepair(res repair.Result) {
	for _, s := range res.Steps {
		status := "ok"
		if !s.OK {
			status = "fail"
		}
		if s.Detail != "" {
			fmt.Printf("repair %s: %s (%s)\n", s.Name, status, s.Detail)
			continue
		}
		fmt.Printf("repair %s: %s\n", s.Name, status)
	}
}

func mustServiceControl(action string) {
	if action == "install" || action == "uninstall" {
		if err := elevateIfNeeded(action); err != nil {
			slog.Error(action, "err", err)
			os.Exit(1)
		}
	}
	if action == "install" {
		if err := prepareServiceInstall(); err != nil {
			slog.Error(action, "err", err)
			os.Exit(1)
		}
	}
	p := appservice.NewProgram()
	svc, err := appservice.NewService(p)
	if err != nil {
		slog.Error(action, "err", err)
		os.Exit(1)
	}
	var opErr error
	switch action {
	case "install":
		opErr = svc.Install()
		if opErr == nil {
			afterInstall()
		}
	case "uninstall":
		opErr = svc.Uninstall()
		if opErr == nil {
			afterUninstall()
		}
	case "start":
		opErr = startService(svc)
	case "stop":
		opErr = stopService(svc)
	}
	if opErr != nil {
		slog.Error(action, "err", opErr)
		os.Exit(1)
	}
	fmt.Printf("%s: ok (%s)\n", action, appservice.Name)
}

func mustSetup() {
	if err := elevateIfNeeded("setup"); err != nil {
		slog.Error("setup", "err", err)
		os.Exit(1)
	}
	if err := prepareServiceInstall(); err != nil {
		slog.Error("setup prepare", "err", err)
		os.Exit(1)
	}
	p := appservice.NewProgram()
	svc, err := appservice.NewService(p)
	if err != nil {
		slog.Error("setup", "err", err)
		os.Exit(1)
	}
	st, err := svc.Status()
	if err != nil {
		if err == service.ErrNotInstalled {
			if err := svc.Install(); err != nil {
				slog.Error("setup install", "err", err)
				os.Exit(1)
			}
			fmt.Printf("setup: installed (%s)\n", appservice.Name)
			st = service.StatusStopped
		} else {
			slog.Error("setup status", "err", err)
			os.Exit(1)
		}
	}
	if st != service.StatusRunning {
		if err := startService(svc); err != nil {
			slog.Error("setup start", "err", err)
			os.Exit(1)
		}
		fmt.Printf("setup: started (%s)\n", appservice.Name)
	} else {
		fmt.Printf("setup: already running (%s)\n", appservice.Name)
	}
	// Demand-start: UI owns lifecycle (quit → stop). Re-apply after older Automatic installs.
	configureDemandStart()
}

func printServiceStatus() {
	if s, ok := probeStatus(); ok {
		fmt.Printf("%s: %s\n", appservice.Name, s)
		return
	}
	p := appservice.NewProgram()
	svc, err := appservice.NewService(p)
	if err != nil {
		slog.Error("status", "err", err)
		os.Exit(1)
	}
	st, err := svc.Status()
	if err != nil {
		if err == service.ErrNotInstalled {
			fmt.Printf("%s: not installed\n", appservice.Name)
			return
		}
		slog.Error("status", "err", err)
		os.Exit(1)
	}
	name := map[service.Status]string{
		service.StatusUnknown: "unknown",
		service.StatusRunning: "running",
		service.StatusStopped: "stopped",
	}[st]
	fmt.Printf("%s: %s\n", appservice.Name, name)
}

func runClient(method string) error {
	return runClientWithTimeout(method, 25*time.Second)
}

func runClientWithTimeout(method string, timeout time.Duration) error {
	if method == "diagnostics" {
		fmt.Fprintln(os.Stderr, "Requesting diagnostics; waiting for the daemon response...")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := requestRPC(ctx, method)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(ipc.Response{ID: "1", OK: true, Result: result}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func requestRPC(ctx context.Context, method string) (json.RawMessage, error) {
	conn, err := dialPipe(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bound the whole RPC so a hung start cannot stall forever.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	req := ipc.Request{ID: "1", Method: method, Params: map[string]any{}}
	if method == "start" {
		req.Params["mode"] = "auto"
	}
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	if err := enc.Encode(req); err != nil {
		return nil, err
	}
	var resp struct {
		ID     string          `json:"id"`
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *ipc.RPCError   `json:"error"`
	}
	if err := dec.Decode(&resp); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("empty response")
		}
		return nil, err
	}
	if resp.ID != req.ID {
		return nil, fmt.Errorf("IPC response ID mismatch")
	}
	if !resp.OK {
		if resp.Error == nil {
			return nil, fmt.Errorf("RPC failed without an error description")
		}
		return nil, fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
	}
	return resp.Result, nil
}
