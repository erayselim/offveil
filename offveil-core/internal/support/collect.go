// Package support collects a support bundle without requiring a running daemon.
package support

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/appdir"
	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/version"
)

type RPC func(context.Context, string) (json.RawMessage, error)

// Collect uses a bounded IPC attempt, then falls back to local installation facts.
// It never starts protection, launches a daemon, requests elevation or changes DNS.
func Collect(ctx context.Context, rpc RPC) diag.Input {
	in := diag.Input{Cascade: diag.CascadeInfo{State: "unavailable", Summary: "Daemon status unavailable"}}
	system := installationFacts()
	system["collector_version"] = version.Version
	system["os"] = runtime.GOOS
	system["architecture"] = runtime.GOARCH
	system["collection_mode"] = "offline"
	system["protection_state"] = "unknown"
	platformFacts(ctx, system)
	if rpc != nil {
		rpcCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		raw, err := rpc(rpcCtx, "diagnostics")
		cancel()
		if err == nil {
			var meta diag.BundleMeta
			if err = json.Unmarshal(raw, &meta); err == nil {
				var live diag.Input
				if len(meta.Report) > 0 {
					err = json.Unmarshal(meta.Report, &live)
				} else {
					// Daemons before 1.1 return only a path under a root-owned
					// directory; this works only for privileged collectors.
					live, err = readLiveBundle(meta.Path)
				}
				if err == nil {
					in = live
					system["collection_mode"] = "live"
					system["daemon_version"] = meta.Version
					// Cascade may be a retained active snapshot after Stop. Only
					// an explicit current-state fact is authoritative.
					if state, ok := live.System["protection_state"].(string); ok && (state == "on" || state == "off") {
						system["protection_state"] = state
					}
					if len(live.System) > 0 {
						system["daemon"] = live.System
					}
				}
			}
		}
		if err != nil {
			system["daemon_error"] = diag.Scrub(err.Error())
			in.Notes = append(in.Notes, "Daemon did not provide a support snapshot; local installation facts were collected instead. Protection state is unknown.")
		}
	}
	in.System = system
	if len(in.Failures) == 0 {
		in.Failures = diag.ReadFailures()
	}
	in.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	return in
}

func readLiveBundle(path string) (diag.Input, error) {
	var in diag.Input
	root, err := diag.Dir()
	if err != nil {
		return in, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return in, err
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return in, err
	}
	rel, err := filepath.Rel(root, canonical)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return in, fmt.Errorf("daemon returned a path outside the diagnostics directory")
	}
	zr, err := zip.OpenReader(canonical)
	if err != nil {
		return in, err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "diagnostics.json" {
			continue
		}
		if f.UncompressedSize64 > 4<<20 {
			return in, fmt.Errorf("diagnostics snapshot too large")
		}
		r, err := f.Open()
		if err != nil {
			return in, err
		}
		defer r.Close()
		err = json.NewDecoder(io.LimitReader(r, 4<<20)).Decode(&in)
		return in, err
	}
	return in, fmt.Errorf("diagnostics snapshot is missing")
}

func installationFacts() map[string]any {
	facts := map[string]any{}
	exe, _ := os.Executable()
	installedDir := appdir.Root()
	if runtime.GOOS == "windows" {
		if pf := os.Getenv("ProgramFiles"); pf != "" {
			installedDir = filepath.Join(pf, "offveil")
		}
	}
	names := []string{"offveil-core", "ciadpi", "sing-box"}
	if runtime.GOOS == "windows" {
		names = append(names, "wintun.dll")
	}
	for _, name := range names {
		binary := name
		if runtime.GOOS == "windows" && name != "wintun.dll" {
			binary += ".exe"
		}
		bundled := filepath.Join(filepath.Dir(exe), binary)
		installed := filepath.Join(installedDir, binary)
		facts[name] = map[string]any{"bundled": fileFact(bundled), "installed": fileFact(installed)}
	}
	if runtime.GOOS == "darwin" {
		facts["launchd_plist"] = fileFact("/Library/LaunchDaemons/offveil-core.plist")
		facts["start_grant"] = fileFact("/etc/sudoers.d/offveil")
		_, err := os.Stat("/var/run/offveil/core.sock")
		facts["system_socket_exists"] = err == nil
		facts["collector_privileged"] = os.Geteuid() == 0
	}
	return facts
}

func fileFact(path string) map[string]any {
	st, err := os.Stat(path)
	if errors.Is(err, fs.ErrPermission) {
		// A root-only directory hides the file from this collector; that
		// says nothing about whether it is installed.
		return map[string]any{"exists": "unknown", "error": "permission denied"}
	}
	if err != nil {
		return map[string]any{"exists": false, "error": diag.Scrub(err.Error())}
	}
	fact := map[string]any{"exists": true, "size": st.Size(), "mode": st.Mode().String()}
	if !st.Mode().IsRegular() || st.Size() > 128<<20 {
		return fact
	}
	f, err := os.Open(path)
	if err != nil {
		fact["error"] = diag.Scrub(err.Error())
		return fact
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err == nil {
		fact["sha256"] = hex.EncodeToString(h.Sum(nil))
	}
	return fact
}

// Write produces a complete ZIP in a user-selected destination. With no output,
// it uses Downloads (or the home directory when Downloads is absent).
func Write(in diag.Input, output string) (*diag.BundleMeta, error) {
	var dir string
	if output == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(home, "Downloads")
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			dir = home
		}
	} else {
		if !strings.EqualFold(filepath.Ext(output), ".zip") {
			return nil, fmt.Errorf("support output must end in .zip")
		}
		var err error
		output, err = filepath.Abs(output)
		if err != nil {
			return nil, err
		}
		dir = filepath.Dir(output)
	}
	meta, err := diag.WriteZipIn(in, dir)
	if err != nil {
		return nil, err
	}
	if output != "" {
		if err := os.Rename(meta.Path, output); err != nil {
			_ = os.Remove(meta.Path)
			return nil, err
		}
		meta.Path = output
	}
	meta.Note = "Support bundle saved; mode=" + fmt.Sprint(in.System["collection_mode"])
	return meta, nil
}
