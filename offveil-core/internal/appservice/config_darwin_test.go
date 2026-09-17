//go:build darwin

package appservice

import "testing"

func TestDarwinConfigDemandStart(t *testing.T) {
	cfg := Config()
	if cfg.Name != Name {
		t.Fatalf("Name=%s", cfg.Name)
	}
	if v, _ := cfg.Option["KeepAlive"].(bool); v {
		t.Fatal("KeepAlive must be false")
	}
	if v, _ := cfg.Option["RunAtLoad"].(bool); v {
		t.Fatal("RunAtLoad must be false")
	}
	if v, _ := cfg.Option["UserService"].(bool); v {
		t.Fatal("UserService must be false")
	}
	if _, ok := cfg.Option["StartType"]; ok {
		t.Fatal("Darwin Config must not set Windows StartType")
	}
}
