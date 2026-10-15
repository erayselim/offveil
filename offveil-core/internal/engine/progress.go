package engine

import (
	"encoding/json"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
	"github.com/erayselim/offveil/offveil-core/internal/ipc"
)

// Serialized copies cannot alias mutable session state. Readers never call
// sidecars or wait for the lifecycle lock to get a startup support snapshot.
type operationSnapshot struct {
	status []byte
	diag   []byte
}

func (e *Engine) publishOperationLocked(stage string) {
	in := e.buildDiagInputLocked()
	in.Notes = append(in.Notes, "snapshot_created_at="+in.CreatedAt)
	if stage != "" {
		in.Notes = append(in.Notes, "Engine operation in progress; startup_stage="+stage)
	}
	status, statusErr := json.Marshal(e.statusLocked())
	support, diagErr := json.Marshal(in)
	if statusErr == nil && diagErr == nil {
		e.operation.Store(&operationSnapshot{status: status, diag: support})
	}
}

func (s *operationSnapshot) statusCopy() *ipc.Status {
	var st ipc.Status
	_ = json.Unmarshal(s.status, &st) // Stored only after successful encoding.
	return &st
}

func (s *operationSnapshot) writeDiagnostics() (*diag.BundleMeta, error) {
	var in diag.Input
	if err := json.Unmarshal(s.diag, &in); err != nil {
		return nil, err
	}
	in.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	in.Notes = append(in.Notes,
		"Engine is busy; this is the last published snapshot. Pending stages may not be included.")
	return writeDiagnostics(in)
}
