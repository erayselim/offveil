package ruleset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// LoadOptions controls Load.
type LoadOptions struct {
	// SkipRemote disables the update channel fetch.
	SkipRemote bool
	// PublicKeyHex overrides channel.json (tests / emergency rotate).
	PublicKeyHex string
	// RequireSig for cache/remote (bundled is always trusted at build time).
	RequireSig bool
	// HTTPClient optional.
	HTTPClient *http.Client
	// Now for tests.
	Now func() time.Time
}

// Load resolves ruleset: cache (verified) → repo file → embedded, then optional remote refresh.
func Load(ctx context.Context, opts LoadOptions) (Snapshot, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 4 * time.Second}
	}
	ch, err := ParseChannel(BundledChannel())
	if err != nil {
		return Snapshot{}, err
	}
	if u := strings.TrimSpace(os.Getenv("OFFVEIL_RULESET_URL")); u != "" {
		ch.BaseURL = strings.TrimRight(u, "/")
	}
	pubHex := opts.PublicKeyHex
	if pubHex == "" {
		pubHex = ch.PublicKeyHex
	}
	if pubHex == "" {
		pubHex = DefaultPublicKeyHex
	}

	var snap Snapshot

	// 1) Verified cache
	if cacheDir, err := CacheDir(); err == nil {
		jp := filepath.Join(cacheDir, ch.RulesetFile)
		sp := filepath.Join(cacheDir, ch.SignatureFile)
		if s, err := LoadFile(jp, sp, pubHex, true); err == nil {
			s.Source = "cache"
			s.LoadedAt = opts.Now()
			snap = s
			slog.Info("ruleset: loaded cache", "version", s.Doc.Version, "sha256", s.SHA256Hex[:12])
		}
	}

	// 2) Repo / beside-exe (dev) - verify if .sig present
	if snap.Doc.Version == 0 {
		if jp, sp, ok := FindRepoRuleset(); ok {
			if s, err := LoadFile(jp, sp, pubHex, false); err == nil {
				s.Source = "file"
				s.LoadedAt = opts.Now()
				snap = s
				slog.Info("ruleset: loaded file", "path", jp, "version", s.Doc.Version)
			}
		}
	}

	// 3) Embedded bundle (always available)
	if snap.Doc.Version == 0 {
		doc, err := ParseDocument(BundledActive())
		if err != nil {
			return Snapshot{}, fmt.Errorf("embedded ruleset: %w", err)
		}
		raw := BundledActive()
		// Prefer verifying embedded against bundled sig if present in embed - we copy sig too.
		snap = Snapshot{
			Doc:       doc,
			Source:    "embedded",
			LoadedAt:  opts.Now(),
			SHA256Hex: sha256Hex(raw),
		}
		slog.Info("ruleset: loaded embedded", "version", doc.Version, "sha256", snap.SHA256Hex[:12])
	}

	if opts.SkipRemote {
		return snap, nil
	}

	// 4) Remote update (best-effort)
	updated, err := tryRemoteUpdate(ctx, opts.HTTPClient, ch, pubHex, snap, opts.Now)
	if err != nil {
		slog.Warn("ruleset: remote update skipped", "err", err)
		return snap, nil
	}
	if updated != nil {
		return *updated, nil
	}
	return snap, nil
}

func tryRemoteUpdate(ctx context.Context, client *http.Client, ch Channel, pubHex string, current Snapshot, now func() time.Time) (*Snapshot, error) {
	cacheDir, err := CacheDir()
	if err != nil {
		return nil, err
	}
	metaPath := filepath.Join(cacheDir, "last_check.txt")
	if b, err := os.ReadFile(metaPath); err == nil {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b))); err == nil {
			interval := time.Duration(ch.UpdateIntervalHours) * time.Hour
			if now().Sub(t) < interval && current.Source == "cache" {
				return nil, nil
			}
		}
	}

	base := strings.TrimRight(ch.BaseURL, "/")
	jsonURL := base + "/" + ch.RulesetFile
	sigURL := base + "/" + ch.SignatureFile

	raw, err := httpGet(ctx, client, jsonURL)
	if err != nil {
		_ = os.MkdirAll(cacheDir, 0755)
		_ = os.WriteFile(metaPath, []byte(now().UTC().Format(time.RFC3339)+"\n"), 0644)
		return nil, err
	}
	sigB64, err := httpGet(ctx, client, sigURL)
	if err != nil {
		return nil, err
	}
	if err := VerifyHexKey(pubHex, raw, string(sigB64)); err != nil {
		return nil, err
	}
	doc, err := ParseDocument(raw)
	if err != nil {
		return nil, err
	}
	if ch.MinRulesetVersion > 0 && doc.Version < ch.MinRulesetVersion {
		return nil, fmt.Errorf("remote ruleset version %d < min %d", doc.Version, ch.MinRulesetVersion)
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, err
	}
	jp := filepath.Join(cacheDir, ch.RulesetFile)
	sp := filepath.Join(cacheDir, ch.SignatureFile)
	tmpJ := jp + ".tmp"
	tmpS := sp + ".tmp"
	if err := os.WriteFile(tmpJ, raw, 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(tmpS, []byte(strings.TrimSpace(string(sigB64))+"\n"), 0644); err != nil {
		_ = os.Remove(tmpJ)
		return nil, err
	}
	if err := os.Rename(tmpJ, jp); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpS, sp); err != nil {
		return nil, err
	}
	_ = os.WriteFile(metaPath, []byte(now().UTC().Format(time.RFC3339)+"\n"), 0644)

	snap := Snapshot{
		Doc:       doc,
		Source:    "remote",
		LoadedAt:  now(),
		SHA256Hex: sha256Hex(raw),
	}
	slog.Info("ruleset: updated from channel", "url", jsonURL, "version", doc.Version, "sha256", snap.SHA256Hex[:12])
	return &snap, nil
}

func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "offveil-core-ruleset/1.8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 2<<20))
}

// MustLoad is Load with SkipRemote for tests / early boot; panics only on total failure.
func MustLoadEmbedded() Snapshot {
	doc, err := ParseDocument(BundledActive())
	if err != nil {
		panic(err)
	}
	return Snapshot{
		Doc:       doc,
		Source:    "embedded",
		LoadedAt:  time.Now(),
		SHA256Hex: sha256Hex(BundledActive()),
	}
}
