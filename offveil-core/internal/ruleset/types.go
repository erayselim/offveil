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

// KindCanary marks crisis-day throttle packages (not status cards).
const KindCanary = "canary"

// Package is one curated domain set (discord, direct-games, canary, …).
type Package struct {
	ID             string   `json:"id"`
	Label          string   `json:"label"`
	Kind           string   `json:"kind,omitempty"` // "" special | "canary"
	DefaultEnabled bool     `json:"default_enabled"`
	PathForce      string   `json:"path_force,omitempty"` // "direct" | "desync" | "tunnel"
	Domains        []string `json:"domains,omitempty"`
	DomainSuffix   []string `json:"domain_suffix,omitempty"`
	ResolveHosts   []string `json:"resolve_hosts,omitempty"`
	ProbeHosts     []string `json:"probe_hosts,omitempty"`
	Notes          string   `json:"notes,omitempty"`
}

// IsCanary is crisis-day throttle/IP-drop → selective tunnel, not a status card.
func (p Package) IsCanary() bool {
	return strings.EqualFold(p.Kind, KindCanary)
}

// Channel describes the signed remote update endpoint.
type Channel struct {
	Name                string `json:"name"`
	Version             int    `json:"version"`
	BaseURL             string `json:"base_url"`
	RulesetFile         string `json:"ruleset_file"`
	SignatureFile       string `json:"signature_file"`
	PublicKeyHex        string `json:"public_key_hex"`
	UpdateIntervalHours int    `json:"update_interval_hours"`
	MinRulesetVersion   int    `json:"min_ruleset_version"`
	Notes               string `json:"notes,omitempty"`
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

// RouteHosts is domains + suffixes used for sing-box special routing.
func (p Package) RouteHosts() []string {
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
	for _, x := range p.Domains {
		add(x)
	}
	for _, x := range p.DomainSuffix {
		add(x)
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
		if p.PathForce == "direct" || p.IsCanary() {
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

// ResolveHosts are concrete hosts used as capture resolve seeds.
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
		if p.PathForce == "direct" || p.IsCanary() {
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

// ProbeHosts are session-start cascade targets (special packages only).
func (d Document) ProbeHosts() []string {
	return d.probeHosts(false)
}

// CanaryProbeHosts are background crisis-day targets (not session-start).
func (d Document) CanaryProbeHosts() []string {
	return d.probeHosts(true)
}

func (d Document) probeHosts(canary bool) []string {
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
		if p.IsCanary() != canary {
			continue
		}
		if len(p.ProbeHosts) > 0 {
			for _, x := range p.ProbeHosts {
				add(x)
			}
			continue
		}
		if !canary && len(p.Domains) > 0 {
			add(p.Domains[0])
		}
	}
	if !canary && len(out) == 0 {
		out = []string{"discord.com"}
	}
	return out
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "*.")
	for len(h) > 0 && h[0] == '.' {
		// Strip a leading dot so JSON suffix entries match sing-box domain_suffix
		// ("discord.com", not ".discord.com").
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
