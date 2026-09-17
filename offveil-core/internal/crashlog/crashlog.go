// Package crashlog writes panic text to the machine data dir (logs/).
// No minidump: SYSTEM process memory would leak PII / packet scraps.
package crashlog

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/appdir"
)

// Dir is the panic / slog fallback directory.
func Dir() string {
	if d := os.Getenv("OFFVEIL_LOG_DIR"); d != "" {
		return d
	}
	return filepath.Join(appdir.Root(), "logs")
}

// WritePanic stores recovered panic + stack. Best-effort; never panics.
func WritePanic(rec any) {
	defer func() { _ = recover() }()
	dir := Dir()
	_ = os.MkdirAll(dir, 0755)
	name := fmt.Sprintf("panic-%s.log", time.Now().UTC().Format("20060102T150405Z"))
	buf := make([]byte, 16<<10)
	n := runtime.Stack(buf, false)
	body := fmt.Sprintf("time=%s\npanic=%v\n\n%s\n", time.Now().UTC().Format(time.RFC3339), rec, buf[:n])
	_ = os.WriteFile(filepath.Join(dir, name), []byte(body), 0600)
}

// Guard recovers a goroutine panic, logs it, then re-panics so SCM can restart.
func Guard() {
	if rec := recover(); rec != nil {
		WritePanic(rec)
		panic(rec)
	}
}
