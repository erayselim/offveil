package ruleset

import (
	"strings"
)

// Suggestion is a domain-expansion proposal for half-loaded legacy content.
// Runtime may auto-apply /32 TUN routes; UI may ignore and only diagnostics use it.
type Suggestion struct {
	PackageID string `json:"package_id"`
	Host      string `json:"host"`
	Reason    string `json:"reason"` // dns_observed | cdn_sibling | resolve_seed
}

// TargetSeed is a curated package row for status.targets (non-direct).
type TargetSeed struct {
	ID    string
	Label string
}

// MatchPackage returns the first enabled non-direct package covering host.
func (d Document) MatchPackage(host string) (Package, bool) {
	h := normalizeHost(host)
	if h == "" {
		return Package{}, false
	}
	for _, p := range d.EnabledPackages() {
		if p.PathForce == "direct" {
			continue
		}
		if packageCovers(p, h) {
			return p, true
		}
	}
	return Package{}, false
}

// Covers reports whether package includes host via domains or domain_suffix.
func (p Package) Covers(host string) bool {
	return packageCovers(p, normalizeHost(host))
}

func packageCovers(p Package, h string) bool {
	if h == "" {
		return false
	}
	for _, d := range p.Domains {
		if h == normalizeHost(d) {
			return true
		}
	}
	for _, s := range p.DomainSuffix {
		suf := normalizeHost(s)
		if suf == "" {
			continue
		}
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	return false
}

// ExpandForHost builds sibling CDN / resolve-seed suggestions when a package
// host is observed (DNS or probe). Skips hosts already present in already.
//
// Typical half-load case: secure.imvu.com works but webasset-akm.imvu.com was
// never routed - ExpandForHost proposes the package resolve_hosts set.
func (d Document) ExpandForHost(observed string, already map[string]struct{}) []Suggestion {
	h := normalizeHost(observed)
	if h == "" {
		return nil
	}
	pkg, ok := d.MatchPackage(h)
	if !ok {
		return nil
	}
	seen := map[string]struct{}{}
	var out []Suggestion
	add := func(host, reason string) {
		host = normalizeHost(host)
		if host == "" || strings.HasPrefix(host, ".") {
			return
		}
		if _, ok := already[host]; ok {
			return
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		out = append(out, Suggestion{
			PackageID: pkg.ID,
			Host:      host,
			Reason:    reason,
		})
	}

	if packageCovers(pkg, h) {
		add(h, "dns_observed")
	}
	if len(pkg.ResolveHosts) > 0 {
		for _, rh := range pkg.ResolveHosts {
			reason := "resolve_seed"
			if rh != h {
				reason = "cdn_sibling"
			}
			add(rh, reason)
		}
		return out
	}
	for _, dom := range pkg.Domains {
		if looksLikeCDN(dom) {
			add(dom, "cdn_sibling")
		}
	}
	return out
}

func looksLikeCDN(host string) bool {
	h := normalizeHost(host)
	return strings.Contains(h, "cdn") ||
		strings.Contains(h, "akm") ||
		strings.Contains(h, "asset") ||
		strings.Contains(h, "static") ||
		strings.Contains(h, "media") ||
		strings.Contains(h, "userimages")
}

// TargetSeeds lists enabled curated packages for tray/status (skips direct-games).
func (d Document) TargetSeeds() []TargetSeed {
	var out []TargetSeed
	for _, p := range d.EnabledPackages() {
		if p.PathForce == "direct" {
			continue
		}
		label := p.Label
		if label == "" {
			label = p.ID
		}
		out = append(out, TargetSeed{ID: p.ID, Label: label})
	}
	if len(out) == 0 {
		out = []TargetSeed{{ID: "discord", Label: "Discord"}}
	}
	return out
}

// PackageIDForHost returns the package id covering host, or "".
func (d Document) PackageIDForHost(host string) string {
	if p, ok := d.MatchPackage(host); ok {
		return p.ID
	}
	return ""
}
