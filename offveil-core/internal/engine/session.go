package engine

import "context"

// All helpers in this file require e.mu.
func (e *Engine) beginSessionLocked() {
	e.cancelSessionLocked()
	e.sessionCtx, e.sessionCancel = context.WithCancel(context.Background())
}

func (e *Engine) cancelSessionLocked() {
	e.sessionGeneration++
	e.strategySwitching = false
	if e.sessionCancel != nil {
		e.sessionCancel()
		e.sessionCancel = nil
	}
	e.sessionCtx = nil
}

func (e *Engine) sessionContextLocked() context.Context {
	if e.sessionCtx != nil {
		return e.sessionCtx
	}
	return context.Background()
}

func (e *Engine) currentSessionLocked(generation uint64) bool {
	return generation == e.sessionGeneration && e.protection &&
		(e.state == StateActive || e.state == StateDegraded)
}
