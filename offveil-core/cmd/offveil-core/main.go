package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/kardianos/service"

	"github.com/erayselim/offveil/offveil-core/internal/appservice"
	"github.com/erayselim/offveil/offveil-core/internal/crashlog"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/version"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if len(os.Args) < 2 {
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
		mustServiceControl("uninstall")
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
		_ = clientFlags.Parse(os.Args[2:])
		if err := runClient(*method); err != nil {
			fmt.Fprintf(os.Stderr, "client: %v\n", err)
			os.Exit(1)
		}
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
	fmt.Fprintf(os.Stderr, `offveil-core - offveil Windows daemon

Usage:
  offveil-core                 Run as Windows Service (SCM)
  offveil-core run             Interactive foreground (dev)
  offveil-core install         Install Windows Service "offveil-core"
  offveil-core uninstall       Remove Windows Service
  offveil-core setup           Install (if needed) + start - single elevation for UI
  offveil-core start|stop      Control installed service
  offveil-core status          Query SCM status
  offveil-core client -method ping|status|start|stop|restart|health|test|repair
  offveil-core version

IPC: %s
`, ipc.PipePath)
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

func mustServiceControl(action string) {
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
	case "uninstall":
		opErr = svc.Uninstall()
	case "start":
		opErr = svc.Start()
	case "stop":
		opErr = svc.Stop()
	}
	if opErr != nil {
		slog.Error(action, "err", opErr)
		os.Exit(1)
	}
	fmt.Printf("%s: ok (%s)\n", action, appservice.Name)
}

func mustSetup() {
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
		if err := svc.Start(); err != nil {
			slog.Error("setup start", "err", err)
			os.Exit(1)
		}
		fmt.Printf("setup: started (%s)\n", appservice.Name)
	} else {
		fmt.Printf("setup: already running (%s)\n", appservice.Name)
	}
	// Demand-start: UI owns lifecycle (quit → stop). Re-apply after older Automatic installs.
	configureManualStart()
	configureStartDACL()
}

func configureManualStart() {
	// sc.exe config … start= demand - no UAC needed when already elevated via setup.
	out, err := runSC("config", appservice.Name, "start=", "demand")
	if err != nil {
		slog.Warn("setup: could not set StartType=manual", "err", err, "out", out)
		return
	}
	slog.Info("setup: StartType=manual (UI lifecycle)")
}

// Authenticated Users may StartService without UAC so login auto-connect works.
func configureStartDACL() {
	sddl := "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;AU)"
	out, err := runSC("sdset", appservice.Name, sddl)
	if err != nil {
		slog.Warn("setup: could not set service DACL", "err", err, "out", out)
		return
	}
	slog.Info("setup: AU SERVICE_START granted")
}

func runSC(args ...string) (string, error) {
	cmd := exec.Command("sc.exe", args...)
	b, err := cmd.CombinedOutput()
	return string(b), err
}

func printServiceStatus() {
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
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	conn, err := dialPipe(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Bound the whole RPC so a hung start cannot stall forever.
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))

	req := ipc.Request{ID: "1", Method: method, Params: map[string]any{}}
	if method == "start" {
		req.Params["mode"] = "auto"
	}
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	if err := enc.Encode(req); err != nil {
		return err
	}
	var resp ipc.Response
	if err := dec.Decode(&resp); err != nil {
		if err == io.EOF {
			return fmt.Errorf("empty response")
		}
		return err
	}
	out, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println(string(out))
	if !resp.OK {
		return fmt.Errorf("rpc error: %s", resp.Error.Code)
	}
	return nil
}
