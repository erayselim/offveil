package cleanup

import (
	"log/slog"
	"sync"
)

// Hook is a best-effort cleanup step (routes, DNS, adapters, child engines).
// Later phases (TUN/DNS) register concrete hooks here.
type Hook func() error

// Registry runs registered hooks on stop / crash / service shutdown.
type Registry struct {
	mu    sync.Mutex
	hooks []namedHook
}

type namedHook struct {
	name string
	fn   Hook
}

func NewRegistry() *Registry {
	return &Registry{}
}

// Register appends a named cleanup hook. Order is LIFO on Run.
func (r *Registry) Register(name string, fn Hook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks = append(r.hooks, namedHook{name: name, fn: fn})
}

// Clear removes all hooks (after a clean stop that already ran them).
func (r *Registry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks = nil
}

// Run executes hooks in reverse registration order. Errors are logged, not returned
// as fatal - crash cleanup must be best-effort.
func (r *Registry) Run(reason string) {
	r.mu.Lock()
	hooks := make([]namedHook, len(r.hooks))
	copy(hooks, r.hooks)
	r.mu.Unlock()

	slog.Info("cleanup: running hooks", "reason", reason, "count", len(hooks))
	for i := len(hooks) - 1; i >= 0; i-- {
		h := hooks[i]
		if err := h.fn(); err != nil {
			slog.Warn("cleanup: hook failed", "name", h.name, "reason", reason, "err", err)
		} else {
			slog.Info("cleanup: hook ok", "name", h.name, "reason", reason)
		}
	}
}
