//go:build windows

package capture

import (
	"log/slog"

	"golang.zx2c4.com/wintun"
)

// AdapterPresent is true when a live adapter named AdapterName exists.
func AdapterPresent() bool {
	_, err := FindAdapterLUIDByName(AdapterName)
	return err == nil
}

// CloseOrphanAdapter opens and closes a leftover Wintun adapter named AdapterName.
// Missing adapter is OK. Best-effort: does not fail the caller when the DLL is absent.
func CloseOrphanAdapter() error {
	if !AdapterPresent() {
		return nil
	}
	dllPath, err := LocateDLL()
	if err != nil {
		return err
	}
	if err := ensureDLLLoadable(dllPath); err != nil {
		return err
	}
	adapter, err := wintun.OpenAdapter(AdapterName)
	if err != nil {
		return err
	}
	if err := adapter.Close(); err != nil {
		return err
	}
	slog.Info("capture: orphan adapter closed", "name", AdapterName)
	return nil
}
