package ruleset

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

//go:embed bundled/active.json
var bundledActive []byte

//go:embed bundled/channel.json
var bundledChannel []byte

// BundledActive returns the compile-time ruleset bytes.
func BundledActive() []byte { return append([]byte(nil), bundledActive...) }

// BundledChannel returns the compile-time channel bytes.
func BundledChannel() []byte { return append([]byte(nil), bundledChannel...) }

// CacheDir is where verified remote rulesets are stored.
func CacheDir() (string, error) {
	if d := os.Getenv("OFFVEIL_RULESET_CACHE"); d != "" {
		return d, nil
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "offveil", "ruleset"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "offveil", "ruleset"), nil
}

// FindRepoRuleset looks for ruleset/active.json relative to exe / cwd (dev).
func FindRepoRuleset() (jsonPath, sigPath string, ok bool) {
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "ruleset", "active.json"),
			filepath.Join(dir, "..", "ruleset", "active.json"),
			filepath.Join(dir, "..", "..", "ruleset", "active.json"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "ruleset", "active.json"),
			filepath.Join(wd, "..", "ruleset", "active.json"),
			filepath.Join(wd, "..", "..", "ruleset", "active.json"),
		)
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, p + ".sig", true
		}
	}
	return "", "", false
}

// LoadFile reads JSON (+ optional .sig) and verifies when sig is present or required.
func LoadFile(jsonPath, sigPath, pubHex string, requireSig bool) (Snapshot, error) {
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		return Snapshot{}, err
	}
	var sigB64 string
	if sigPath != "" {
		if b, err := os.ReadFile(sigPath); err == nil {
			sigB64 = string(b)
		} else if requireSig {
			return Snapshot{}, fmt.Errorf("ruleset signature missing: %w", err)
		}
	}
	if sigB64 != "" {
		if pubHex == "" {
			pubHex = DefaultPublicKeyHex
		}
		if err := VerifyHexKey(pubHex, raw, sigB64); err != nil {
			return Snapshot{}, fmt.Errorf("ruleset %s: %w", jsonPath, err)
		}
	} else if requireSig {
		return Snapshot{}, fmt.Errorf("ruleset signature required")
	}
	doc, err := ParseDocument(raw)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Doc:       doc,
		Source:    "file",
		SHA256Hex: sha256Hex(raw),
	}, nil
}
