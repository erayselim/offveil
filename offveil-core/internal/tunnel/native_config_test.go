package tunnel

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeSingBoxConfig(t *testing.T) {
	bin := os.Getenv("OFFVEIL_SINGBOX_TEST")
	if bin == "" {
		t.Skip("set OFFVEIL_SINGBOX_TEST to the pinned sing-box binary")
	}
	build, err := BuildSingBox(BuildParams{Provider: ProviderDesync, EnableTUN: true, SpecialDomains: []string{"discord.com", "imvu.com"}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, build.JSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("native config rejected: %v\n%s", err, out)
	}
}
