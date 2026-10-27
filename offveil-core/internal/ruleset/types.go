package ruleset

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	SchemaVersion = 3
	MinVersion    = 8
)

// Canary kinds. Persistent groups are blocked on most lines and decide
// whether the network performs SNI filtering at all; crisis groups are
// only filtered on specific days and are watched less often.
const (
	CanaryPersistent = "persistent"
	CanaryCrisis     = "crisis"
)

const (
	maxCanaryGroups    = 32
	maxCanaryHosts     = 16
	maxCanarySuffixes  = 64
	maxExclude         = 256
	maxStrategies      = 32
	maxStrategyArgs    = 32
	maxStrategyArgSize = 64
	maxPoisonIPs       = 64
)

// Document is the signed network policy: neutral controls, canary groups that
// measure filtering, direct exceptions and ByeDPI candidates.
type Document struct {
	SchemaVersion int            `json:"schema_version"`
	Version       int            `json:"version"`
	UpdatedAt     string         `json:"updated_at"`
	Network       NetworkPolicy  `json:"network"`
	Canaries      []CanaryGroup  `json:"canaries,omitempty"`
	Exclude       []string       `json:"exclude,omitempty"`
	Strategies    []StrategySpec `json:"strategies,omitempty"`
	PoisonIPs     []string       `json:"poison_ips,omitempty"`
	Packages      []Package      `json:"packages,omitempty"`
}

// CanaryGroup is a set of destinations that are filtered together. ProbeHosts
// are measured; DomainSuffix decides which traffic follows the group's path.
type CanaryGroup struct {
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Kind         string   `json:"kind"`
	ProbeHosts   []string `json:"probe_hosts"`
	DomainSuffix []string `json:"domain_suffix"`
}

// StrategySpec is a ByeDPI argument candidate. Platform is "windows",
// "darwin" or empty for both. The engine validates flags before use.
type StrategySpec struct {
	ID       string   `json:"id"`
	Platform string   `json:"platform,omitempty"`
	Args     []string `json:"args"`
}

type NetworkPolicy struct {
	ControlHosts []string    `json:"control_hosts"`
	Routes       []RouteRule `json:"routes,omitempty"`
}

// RouteRule is an optional user-selected route; no service rules are built in.
type RouteRule struct {
	Domains      []string `json:"domains,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Path         string   `json:"path"`
}

// DefaultControlHosts spans independent public services. The engine evaluates
// the aggregate result rather than treating a single host as network health.
func DefaultControlHosts() []string {
	return []string{"www.cloudflare.com", "www.microsoft.com", "example.com"}
}

// KindCanary is retained for explicitly configured background domain groups.
const KindCanary = "canary"

// Package remains a compatibility type for callers migrating to network rules.
// Schema 2 documents reject nonempty package lists.
type Package struct {
	ID             string   `json:"id"`
	Label          string   `json:"label"`
	Kind           string   `json:"kind,omitempty"`
	DefaultEnabled bool     `json:"default_enabled"`
	PathForce      string   `json:"path_force,omitempty"`
	Domains        []string `json:"domains,omitempty"`
	DomainSuffix   []string `json:"domain_suffix,omitempty"`
	ResolveHosts   []string `json:"resolve_hosts,omitempty"`
	ProbeHosts     []string `json:"probe_hosts,omitempty"`
	Notes          string   `json:"notes,omitempty"`
}

func (p Package) IsCanary() bool { return strings.EqualFold(p.Kind, KindCanary) }

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
	Source    string
	LoadedAt  time.Time
	SHA256Hex string
}

// ParseDocument rejects obsolete application-specific schemas even when signed.
func ParseDocument(raw []byte) (Document, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Document{}, fmt.Errorf("ruleset json: %w", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		return Document{}, fmt.Errorf("ruleset: unsupported schema %d (want %d)", doc.SchemaVersion, SchemaVersion)
	}
	if doc.Version < MinVersion {
		return Document{}, fmt.Errorf("ruleset: version %d below network policy minimum %d", doc.Version, MinVersion)
	}
	if len(doc.Packages) != 0 {
		return Document{}, fmt.Errorf("ruleset: destination packages are unsupported; migrate to explicit network routes")
	}
	doc.Network.ControlHosts = uniqueHosts(doc.Network.ControlHosts)
	if len(doc.Network.ControlHosts) < 2 || len(doc.Network.ControlHosts) > 16 {
		return Document{}, fmt.Errorf("ruleset: two to sixteen distinct network control hosts are required")
	}
	for _, host := range doc.Network.ControlHosts {
		if !validHostname(host) {
			return Document{}, fmt.Errorf("ruleset: invalid network control host %q", host)
		}
	}
	for i, rule := range doc.Network.Routes {
		if rule.Path != "direct" {
			return Document{}, fmt.Errorf("ruleset: only explicit direct route exceptions are supported (got %q)", rule.Path)
		}
		rule.Domains, rule.DomainSuffix = uniqueHosts(rule.Domains), uniqueHosts(rule.DomainSuffix)
		if len(rule.Domains)+len(rule.DomainSuffix) == 0 {
			return Document{}, fmt.Errorf("ruleset: route requires a destination")
		}
		for _, host := range append(append([]string{}, rule.Domains...), rule.DomainSuffix...) {
			if !validHostname(host) {
				return Document{}, fmt.Errorf("ruleset: invalid route host %q", host)
			}
		}
		doc.Network.Routes[i] = rule
	}
	if err := validateCanaries(&doc); err != nil {
		return Document{}, err
	}
	doc.Exclude = uniqueHosts(doc.Exclude)
	if len(doc.Exclude) > maxExclude {
		return Document{}, fmt.Errorf("ruleset: too many exclude suffixes")
	}
	for _, host := range doc.Exclude {
		if !validHostname(host) {
			return Document{}, fmt.Errorf("ruleset: invalid exclude host %q", host)
		}
	}
	if err := validateStrategies(doc.Strategies); err != nil {
		return Document{}, err
	}
	if len(doc.PoisonIPs) > maxPoisonIPs {
		return Document{}, fmt.Errorf("ruleset: too many poison fingerprints")
	}
	for _, raw := range doc.PoisonIPs {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is4() {
			return Document{}, fmt.Errorf("ruleset: invalid poison fingerprint %q", raw)
		}
	}
	return doc, nil
}

func validateCanaries(doc *Document) error {
	if len(doc.Canaries) > maxCanaryGroups {
		return fmt.Errorf("ruleset: too many canary groups")
	}
	seen := map[string]bool{}
	for i, group := range doc.Canaries {
		if !validGroupID(group.ID) || seen[group.ID] {
			return fmt.Errorf("ruleset: invalid or duplicate canary id %q", group.ID)
		}
		seen[group.ID] = true
		if group.Kind != CanaryPersistent && group.Kind != CanaryCrisis {
			return fmt.Errorf("ruleset: canary %q has unknown kind %q", group.ID, group.Kind)
		}
		group.ProbeHosts, group.DomainSuffix = uniqueHosts(group.ProbeHosts), uniqueHosts(group.DomainSuffix)
		if len(group.ProbeHosts) == 0 || len(group.ProbeHosts) > maxCanaryHosts {
			return fmt.Errorf("ruleset: canary %q needs one to %d probe hosts", group.ID, maxCanaryHosts)
		}
		if len(group.DomainSuffix) == 0 || len(group.DomainSuffix) > maxCanarySuffixes {
			return fmt.Errorf("ruleset: canary %q needs one to %d suffixes", group.ID, maxCanarySuffixes)
		}
		for _, host := range append(append([]string{}, group.ProbeHosts...), group.DomainSuffix...) {
			if !validHostname(host) {
				return fmt.Errorf("ruleset: invalid canary host %q", host)
			}
		}
		for _, host := range group.ProbeHosts {
			if !MatchSuffix(host, group.DomainSuffix) {
				return fmt.Errorf("ruleset: canary %q probe host %q is outside its suffixes", group.ID, host)
			}
		}
		doc.Canaries[i] = group
	}
	return nil
}

func validateStrategies(specs []StrategySpec) error {
	if len(specs) > maxStrategies {
		return fmt.Errorf("ruleset: too many strategies")
	}
	seen := map[string]bool{}
	for _, spec := range specs {
		if spec.ID == "" || len(spec.ID) > 64 || seen[spec.Platform+"|"+spec.ID] {
			return fmt.Errorf("ruleset: invalid or duplicate strategy id %q", spec.ID)
		}
		seen[spec.Platform+"|"+spec.ID] = true
		switch spec.Platform {
		case "", "windows", "darwin":
		default:
			return fmt.Errorf("ruleset: strategy %q has unknown platform %q", spec.ID, spec.Platform)
		}
		if len(spec.Args) == 0 || len(spec.Args) > maxStrategyArgs {
			return fmt.Errorf("ruleset: strategy %q needs one to %d arguments", spec.ID, maxStrategyArgs)
		}
		for _, arg := range spec.Args {
			if arg == "" || len(arg) > maxStrategyArgSize || strings.ContainsAny(arg, "\x00\r\n\\/") {
				return fmt.Errorf("ruleset: strategy %q has an invalid argument", spec.ID)
			}
		}
	}
	return nil
}

func validGroupID(id string) bool {
	if id == "" || len(id) > 32 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// MatchSuffix reports whether host equals or is a subdomain of any suffix.
func MatchSuffix(host string, suffixes []string) bool {
	host = normalizeHost(host)
	for _, suffix := range suffixes {
		suffix = normalizeHost(suffix)
		if suffix != "" && (host == suffix || strings.HasSuffix(host, "."+suffix)) {
			return true
		}
	}
	return false
}

// CanariesOfKind returns groups of one kind in document order.
func (d Document) CanariesOfKind(kind string) []CanaryGroup {
	var out []CanaryGroup
	for _, group := range d.Canaries {
		if group.Kind == kind {
			out = append(out, group)
		}
	}
	return out
}

// ExcludeSuffixes merges exclude entries with explicit direct routes.
func (d Document) ExcludeSuffixes() []string {
	out := append([]string{}, d.Exclude...)
	for _, rule := range d.Network.Routes {
		if rule.Path == "direct" {
			out = append(out, rule.Domains...)
			out = append(out, rule.DomainSuffix...)
		}
	}
	return uniqueHosts(out)
}

// StrategiesFor returns candidates for one GOOS in document order.
func (d Document) StrategiesFor(goos string) []StrategySpec {
	var out []StrategySpec
	for _, spec := range d.Strategies {
		if spec.Platform == "" || spec.Platform == goos {
			out = append(out, spec)
		}
	}
	return out
}

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
	if ch.MinRulesetVersion < MinVersion {
		ch.MinRulesetVersion = MinVersion
	}
	return ch, nil
}

func (d Document) EnabledPackages() []Package {
	var out []Package
	for _, p := range d.Packages {
		if p.DefaultEnabled {
			out = append(out, p)
		}
	}
	return out
}

func (p Package) RouteHosts() []string {
	return uniqueHosts(append(append([]string{}, p.Domains...), p.DomainSuffix...))
}

// RouteDomains returns explicitly configured destinations for one path.
func (d Document) RouteDomains(path string) []string {
	var out []string
	for _, rule := range d.Network.Routes {
		if rule.Path == path {
			out = append(out, rule.Domains...)
			out = append(out, rule.DomainSuffix...)
		}
	}
	for _, p := range d.EnabledPackages() {
		if p.PathForce == path {
			out = append(out, p.RouteHosts()...)
		}
	}
	return uniqueHosts(out)
}

func (d Document) TunnelDomains() []string { return d.RouteDomains("tunnel") }
func (d Document) DirectDomains() []string { return d.RouteDomains("direct") }
func (d Document) ProtectedDomains() []string {
	return uniqueHosts(append(d.RouteDomains("desync"), d.RouteDomains("tunnel")...))
}

// ResolveHosts supplies concrete network controls and optional user seeds.
func (d Document) ResolveHosts() []string {
	out := d.ProbeHosts()
	for _, p := range d.EnabledPackages() {
		if p.PathForce == "direct" {
			continue
		}
		if len(p.ResolveHosts) > 0 {
			out = append(out, p.ResolveHosts...)
		} else {
			out = append(out, p.Domains...)
		}
	}
	return uniqueHosts(out)
}

// ProbeHosts supplies only the network controls, never user destination groups.
func (d Document) ProbeHosts() []string {
	if len(d.Network.ControlHosts) == 0 {
		return DefaultControlHosts()
	}
	return uniqueHosts(d.Network.ControlHosts)
}

// CanaryProbeHosts is an empty compatibility shim. Health is network-wide.
func (d Document) CanaryProbeHosts() []string { return nil }

func uniqueHosts(hosts []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, host := range hosts {
		host = normalizeHost(host)
		if host != "" && !seen[host] {
			out = append(out, host)
			seen[host] = true
		}
	}
	return out
}

func validHostname(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimLeft(host, ".")
	return strings.TrimSuffix(host, ".")
}
