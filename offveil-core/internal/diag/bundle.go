// Package diag writes a local diagnostics zip for support tickets.
// It keeps ASN, cascade path, and error class; it drops credentials,
// SSIDs, MACs, public IPs, and usernames.
package diag

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/version"
)

const bundleVersion = 1

// Input is the sanitized snapshot collected by the engine / IPC layer.
type Input struct {
	CreatedAt string         `json:"created_at"`
	Network   NetworkInfo    `json:"network"`
	Cascade   CascadeInfo    `json:"cascade"`
	Probe     *ProbeInfo     `json:"probe,omitempty"`
	Sidecars  map[string]any `json:"sidecars,omitempty"`
	Ruleset   map[string]any `json:"ruleset,omitempty"`
	Heal      map[string]any `json:"heal,omitempty"`
	Notes     []string       `json:"notes,omitempty"`
}

// NetworkInfo intentionally omits PublicIP (PII).
type NetworkInfo struct {
	ASN         string `json:"asn"`
	ISPHint     string `json:"isp_hint,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// CascadeInfo is the current protection decision surface.
type CascadeInfo struct {
	State        string         `json:"state"`
	Protection   bool           `json:"protection"`
	Summary      string         `json:"summary"`
	OutboundHint string         `json:"outbound_hint,omitempty"`
	Health       string         `json:"health,omitempty"`
	Targets      []TargetRow    `json:"targets,omitempty"`
	ErrorClass   string         `json:"error_class,omitempty"` // sanitized class, not raw paths
	LastError    string         `json:"last_error,omitempty"`  // scrubbed message
}

// TargetRow is one curated package outcome.
type TargetRow struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Outcome string `json:"outcome"`
	Path    string `json:"path"`
}

// ProbeInfo is the last probe report without host PII beyond curated domains.
type ProbeInfo struct {
	ASN     string      `json:"asn,omitempty"`
	ISPHint string      `json:"isp_hint,omitempty"`
	Results []ProbeRow  `json:"results,omitempty"`
}

// ProbeRow is one probe classification.
type ProbeRow struct {
	Target string `json:"target"`
	Class  string `json:"class"`
	Path   string `json:"path"`
	OK     bool   `json:"ok"`
}

// BundleMeta is returned by IPC `diagnostics`.
type BundleMeta struct {
	Path      string `json:"path"`
	CreatedAt string `json:"created_at"`
	SHA256    string `json:"sha256"`
	Version   string `json:"version"`
	Note      string `json:"note,omitempty"`
}

// Dir returns ProgramData/offveil/diagnostics (or OFFVEIL_DIAG_DIR).
func Dir() (string, error) {
	if d := os.Getenv("OFFVEIL_DIAG_DIR"); d != "" {
		return d, nil
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "offveil", "diagnostics"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "offveil", "diagnostics"), nil
}

// WriteZip creates diagnostics-<timestamp>.zip under Dir and returns meta.
func WriteZip(in Input) (*BundleMeta, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if in.CreatedAt == "" {
		in.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	in.Cascade.LastError = Scrub(in.Cascade.LastError)
	in.Cascade.ErrorClass = ClassifyError(in.Cascade.LastError, in.Cascade.ErrorClass)
	if scrubbed := ScrubTree(in.Sidecars); scrubbed != nil {
		if m, ok := scrubbed.(map[string]any); ok {
			in.Sidecars = m
		}
	}
	in.Notes = append([]string{
		"PII policy: no public IP, SSID, MAC, username, credentials, or subscription URLs.",
		"Safe to share with support after a quick visual review.",
	}, in.Notes...)

	envelope := map[string]any{
		"bundle_version":     bundleVersion,
		"core_version":       version.Version,
		"contracts_version":  version.ContractsVersion,
		"created_at":         in.CreatedAt,
		"network":            in.Network,
		"cascade":            in.Cascade,
		"probe":              in.Probe,
		"sidecars":           in.Sidecars,
		"ruleset":            in.Ruleset,
		"heal":               in.Heal,
		"notes":              in.Notes,
	}

	raw, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	sha := hex.EncodeToString(sum[:])

	stamp := time.Now().UTC().Format("20060102-150405")
	name := fmt.Sprintf("offveil-diag-%s.zip", stamp)
	path := filepath.Join(dir, name)

	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	if err := writeZipFile(zw, "diagnostics.json", raw); err != nil {
		_ = zw.Close()
		_ = os.Remove(path)
		return nil, err
	}
	summary := buildSummary(in, sha)
	if err := writeZipFile(zw, "summary.md", []byte(summary)); err != nil {
		_ = zw.Close()
		_ = os.Remove(path)
		return nil, err
	}
	manifest, _ := json.MarshalIndent(map[string]any{
		"bundle_version": bundleVersion,
		"created_at":     in.CreatedAt,
		"sha256":         sha,
		"files":          []string{"diagnostics.json", "summary.md", "manifest.json"},
		"pii":            "redacted",
	}, "", "  ")
	if err := writeZipFile(zw, "manifest.json", manifest); err != nil {
		_ = zw.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := zw.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}

	return &BundleMeta{
		Path:      path,
		CreatedAt: in.CreatedAt,
		SHA256:    sha,
		Version:   version.Version,
		Note:      "PII-safe diagnostics bundle (ASN, cascade, error class)",
	}, nil
}

func writeZipFile(zw *zip.Writer, name string, body []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func buildSummary(in Input, sha string) string {
	var b strings.Builder
	b.WriteString("# offveil diagnostics\n\n")
	b.WriteString(fmt.Sprintf("- created: %s\n", in.CreatedAt))
	b.WriteString(fmt.Sprintf("- core: %s\n", version.Version))
	b.WriteString(fmt.Sprintf("- sha256(diagnostics.json): %s\n", sha))
	b.WriteString(fmt.Sprintf("- asn: %s\n", in.Network.ASN))
	if in.Network.ISPHint != "" {
		b.WriteString(fmt.Sprintf("- isp_hint: %s\n", in.Network.ISPHint))
	}
	b.WriteString(fmt.Sprintf("- state: %s · protection=%v · hint=%s\n",
		in.Cascade.State, in.Cascade.Protection, in.Cascade.OutboundHint))
	if in.Cascade.ErrorClass != "" {
		b.WriteString(fmt.Sprintf("- error_class: %s\n", in.Cascade.ErrorClass))
	}
	b.WriteString("\n## Targets\n\n")
	for _, t := range in.Cascade.Targets {
		b.WriteString(fmt.Sprintf("- %s (%s): %s → %s\n", t.Label, t.ID, t.Outcome, t.Path))
	}
	if in.Probe != nil && len(in.Probe.Results) > 0 {
		b.WriteString("\n## Last probe\n\n")
		for _, r := range in.Probe.Results {
			b.WriteString(fmt.Sprintf("- %s: %s → %s (ok=%v)\n", r.Target, r.Class, r.Path, r.OK))
		}
	}
	b.WriteString("\n_No public IP / SSID / credentials included._\n")
	return b.String()
}

// Scrub removes likely PII fragments from free-text (paths, usernames, IPv4).
func Scrub(msg string) string {
	if msg == "" {
		return ""
	}
	out := scrubHomePaths(msg)
	out = scrubIPv4(out)
	return out
}

// ScrubTree recursively scrubs string leaves in JSON-shaped trees (sidecars).
func ScrubTree(v any) any {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var node any
	if err := json.Unmarshal(raw, &node); err != nil {
		return v
	}
	return scrubNode(node)
}

func scrubNode(v any) any {
	switch x := v.(type) {
	case string:
		return Scrub(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = scrubNode(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = scrubNode(vv)
		}
		return out
	default:
		return v
	}
}

// Match Windows / Unix home directory prefixes; replace username only.
// Placeholder must not re-match (avoid `\Users\<redacted>` loops).
var (
	winUserPath = regexp.MustCompile(`(?i)(?:[a-z]:)?[/\\]+users[/\\]+[^/\\]+`)
	unixHomePath = regexp.MustCompile(`(?i)(/Users|/home)/[^/\s"']+`)
)

func scrubHomePaths(s string) string {
	s = winUserPath.ReplaceAllString(s, `C:\Users\_`)
	s = unixHomePath.ReplaceAllString(s, `$1/_`)
	return s
}

func scrubIPv4(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if isDigit(s[i]) {
			start := i
			dots := 0
			for i < len(s) && (isDigit(s[i]) || s[i] == '.') {
				if s[i] == '.' {
					dots++
				}
				i++
			}
			token := s[start:i]
			if dots == 3 && looksLikeIPv4(token) {
				b.WriteString("<ip>")
				continue
			}
			b.WriteString(token)
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// ClassifyError maps scrubbed text / hints to a stable error class.
func ClassifyError(scrubbed, hint string) string {
	if hint != "" {
		return hint
	}
	low := strings.ToLower(scrubbed)
	switch {
	case strings.Contains(low, "privilege"), strings.Contains(low, "access is denied"):
		return "privilege"
	case strings.Contains(low, "tun"), strings.Contains(low, "wintun"):
		return "tun_failed"
	case strings.Contains(low, "byedpi"), strings.Contains(low, "desync"):
		return "engine_failed"
	case strings.Contains(low, "tunnel"), strings.Contains(low, "warp"), strings.Contains(low, "sing-box"):
		return "engine_failed"
	case scrubbed == "":
		return ""
	default:
		return "internal"
	}
}
