package ruleset

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Document is the on-disk / wire format (contracts.md §5).
type Document struct {
	Version   int       `json:"version"`
	UpdatedAt string    `json:"updated_at"`
	Packages  []Package `json:"packages"`
}

// Package is one curated domain set (discord, direct-games, …).
type Package struct {
	ID            string   `json:"id"`
	Label         string   `json:"label"`
	DefaultEnabled bool    `json:"default_enabled"`
	PathForce     string   `json:"path_force,omitempty"` // "direct" | "desync" | "tunnel"
	Domains       []string `json:"domains,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	ResolveHosts  []string `json:"resolve_hosts,omitempty"`
	ProbeHosts    []string `json:"probe_hosts,omitempty"`
	Notes         string   `json:"notes,omitempty"`
}

// Channel describes the signed remote update endpoint.
type Channel struct {
	Name                 string `json:"name"`
	Version              int    `json:"version"`
	BaseURL              string `json:"base_url"`
	RulesetFile          string `json:"ruleset_file"`
	SignatureFile        string `json:"signature_file"`
	PublicKeyHex         string `json:"public_key_hex"`
	UpdateIntervalHours  int    `json:"update_interval_hours"`
	MinRulesetVersion    int    `json:"min_ruleset_version"`
	Notes                string `json:"notes,omitempty"`
}

// Snapshot is a loaded, verified ruleset ready for engine use.
type Snapshot struct {
	Doc       Document
	Source    string // "embedded" | "cache" | "file" | "remote"
	LoadedAt  time.Time
	SHA256Hex string
}

// ParseDocument unmarshals and lightly validates a ruleset JSON body.
func ParseDocument(raw []byte) (Document, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Document{}, fmt.Errorf("ruleset json: %w", err)
	}
	if doc.Version < 1 {
		return Document{}, fmt.Errorf("ruleset: missing version")
	}
	if len(doc.Packages) == 0 {
		return Document{}, fmt.Errorf("ruleset: empty packages")
	}
	for _, p := range doc.Packages {
		if strings.TrimSpace(p.ID) == "" {
			return Document{}, fmt.Errorf("ruleset: package missing id")
		}
	}
	return doc, nil
}

// ParseChannel unmarshals channel.json.
func ParseChannel(raw []byte) (Channel, error) {
	var ch Channel
	if err := json.Unmarshal(raw, &ch); err != nil {
		return Channel{}, fmt.Errorf("channel json: %w", err)
	}
	if ch.BaseURL == "" || ch.RulesetFile == "" || ch.SignatureFile == "" || ch.PublicKeyHex == "" {
		return Channel{}, fmt.Errorf("channel: incomplete fields")
	}
	if ch.UpdateIntervalHours <= 0 {
		ch.UpdateIntervalHours = 24
	}
	return ch, nil
}

// EnabledPackages returns packages with default_enabled.
func (d Document) EnabledPackages() []Package {
	out := make([]Package, 0, len(d.Packages))
	for _, p := range d.Packages {
		if p.DefaultEnabled {
			out = append(out, p)
		}
	}
	return out
}

// TunnelDomains merges domain + domain_suffix from non-direct packages (for sing-box).
func (d Document) TunnelDomains() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = normalizeHost(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, p := range d.EnabledPackages() {
		if p.PathForce == "direct" {
			continue
		}
		for _, x := range p.Domains {
			add(x)
		}
		for _, x := range p.DomainSuffix {
			add(x)
		}
	}
	return out
}

// DirectDomains merges path_force=direct package suffixes/domains.
func (d Document) DirectDomains() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = normalizeHost(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, p := range d.EnabledPackages() {
		if p.PathForce != "direct" {
			continue
		}
		for _, x := range p.Domains {
			add(x)
		}
		for _, x := range p.DomainSuffix {
			add(x)
		}
	}
	return out
}

// ResolveHosts are concrete hosts for selected-route /32 seeds.
func (d Document) ResolveHosts() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = normalizeHost(s)
		if s == "" || strings.HasPrefix(s, ".") {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, p := range d.EnabledPackages() {
		if p.PathForce == "direct" {
			continue
		}
		if len(p.ResolveHosts) > 0 {
			for _, x := range p.ResolveHosts {
				add(x)
			}
			continue
		}
		for _, x := range p.Domains {
			add(x)
		}
	}
	return out
}

// ProbeHosts are session-start cascade targets.
func (d Document) ProbeHosts() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = normalizeHost(s)
		if s == "" || strings.HasPrefix(s, ".") {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, p := range d.EnabledPackages() {
		if p.PathForce == "direct" {
			continue
		}
		if len(p.ProbeHosts) > 0 {
			for _, x := range p.ProbeHosts {
				add(x)
			}
			continue
		}
		if len(p.Domains) > 0 {
			add(p.Domains[0])
		}
	}
	if len(out) == 0 {
		out = []string{"discord.com"}
	}
	return out
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "*.")
	for len(h) > 0 && h[0] == '.' {
		// keep leading dot for suffix entries? strip for tunnel domain_suffix list  - 
		// sing-box domain_suffix wants "discord.com" not ".discord.com"
		h = h[1:]
	}
	b := make([]byte, len(h))
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
