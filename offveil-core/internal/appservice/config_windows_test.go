//go:build windows

package appservice

import "testing"

func TestWindowsConfigManualStart(t *testing.T) {
	cfg := Config()
	if cfg.Name != Name {
		t.Fatalf("Name=%s", cfg.Name)
	}
	if v, _ := cfg.Option["StartType"].(string); v != "manual" {
		t.Fatalf("StartType=%v want manual", cfg.Option["StartType"])
	}
	if _, ok := cfg.Option["KeepAlive"]; ok {
		t.Fatal("Windows Config must not set Darwin KeepAlive")
	}
}
