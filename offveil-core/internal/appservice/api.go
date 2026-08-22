package appservice

import (
	"github.com/erayselim/offveil/offveil-core/internal/engine"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
	"github.com/erayselim/offveil/offveil-core/internal/version"
)

// API implements ipc.Handler against the Engine.
type API struct {
	Eng *engine.Engine
	// Shutdown stops protection and asks SCM to stop the Windows service
	// (UI quit). Optional; nil in unit tests.
	Shutdown func()
}

func (a *API) Handle(method string, params map[string]any) (any, *ipc.RPCError) {
	switch method {
	case "ping", "health":
		return ipc.PingResult{
			Version:          version.Version,
			ContractsVersion: version.ContractsVersion,
			Service:          Name,
		}, nil

	case "status":
		return a.Eng.Status(), nil

	case "start":
		mode := "auto"
		if params != nil {
			if v, ok := params["mode"].(string); ok && v != "" {
				mode = v
			}
		}
		st, err := a.Eng.Start(mode)
		if err != nil {
			return st, err
		}
		return st, nil

	case "stop":
		st, err := a.Eng.Stop()
		if err != nil {
			return st, err
		}
		return st, nil

	case "restart":
		// UI “Yenile”: stop (if running) then start - avoids already_running.
		if st := a.Eng.Status(); st.Protection || st.State != engine.StateStopped {
			if _, err := a.Eng.Stop(); err != nil && err.Code != ipc.CodeNotRunning {
				return nil, err
			}
		}
		st, err := a.Eng.Start("auto")
		if err != nil {
			return st, err
		}
		return st, nil

	case "shutdown":
		// UI exit: tear down protection, then stop Windows service (no UAC  -
		// LocalSystem stops itself via SCM).
		if st := a.Eng.Status(); st.Protection || st.State != engine.StateStopped {
			if _, err := a.Eng.Stop(); err != nil && err.Code != ipc.CodeNotRunning {
				return nil, err
			}
		}
		if a.Shutdown != nil {
			a.Shutdown()
		}
		return map[string]any{"ok": true}, nil

	case "test":
		var hosts []string
		if params != nil {
			if raw, ok := params["targets"].([]any); ok {
				for _, v := range raw {
					if s, ok := v.(string); ok && s != "" {
						hosts = append(hosts, s)
					}
				}
			}
		}
		rep, err := a.Eng.Test(hosts)
		if err != nil {
			return nil, err
		}
		out := ipc.TestReport{
			ASN:     rep.ASN,
			ISPHint: rep.ISPHint,
			Results: make([]ipc.TestResult, 0, len(rep.Results)),
		}
		for _, r := range rep.Results {
			out.Results = append(out.Results, ipc.TestResult{
				Target: r.Target,
				Class:  string(r.Class),
				Path:   r.Path,
				OK:     r.OK,
			})
		}
		return out, nil

	case "diagnostics":
		meta, err := a.Eng.Diagnostics()
		if err != nil {
			return nil, &ipc.RPCError{Code: ipc.CodeInternal, Message: err.Error()}
		}
		return ipc.DiagnosticsBundle{
			Path:      meta.Path,
			CreatedAt: meta.CreatedAt,
			SHA256:    meta.SHA256,
			Version:   meta.Version,
			Note:      meta.Note,
		}, nil

	case "repair":
		res, err := a.Eng.Repair()
		if err != nil {
			return res, err
		}
		return res, nil

	default:
		return nil, &ipc.RPCError{Code: ipc.CodeBadRequest, Message: "unknown method: " + method}
	}
}
