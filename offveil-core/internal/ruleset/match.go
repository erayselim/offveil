package ruleset

import "strings"

// Suggestion records an observed destination matched by an explicit user group.
type Suggestion struct {
	PackageID string `json:"package_id"`
	Host      string `json:"host"`
	Reason    string `json:"reason"`
}

type TargetSeed struct {
	ID    string
	Label string
}

// MatchPackage returns an enabled user group covering the observed host.
func (d Document) MatchPackage(host string) (Package, bool) {
	host = normalizeHost(host)
	if host == "" {
		return Package{}, false
	}
	for _, p := range d.EnabledPackages() {
		if p.PathForce != "direct" && packageCovers(p, host) {
			return p, true
		}
	}
	return Package{}, false
}

func (p Package) Covers(host string) bool { return packageCovers(p, normalizeHost(host)) }

func packageCovers(p Package, host string) bool {
	if host == "" {
		return false
	}
	for _, domain := range p.Domains {
		if host == normalizeHost(domain) {
			return true
		}
	}
	for _, suffix := range p.DomainSuffix {
		suffix = normalizeHost(suffix)
		if suffix != "" && (host == suffix || strings.HasSuffix(host, "."+suffix)) {
			return true
		}
	}
	return false
}

// ExpandForHost reports only an actual observed destination. Related names are
// never inferred from naming conventions or seed lists.
func (d Document) ExpandForHost(observed string, already map[string]struct{}) []Suggestion {
	host := normalizeHost(observed)
	if _, exists := already[host]; exists {
		return nil
	}
	pkg, ok := d.MatchPackage(host)
	if !ok {
		return nil
	}
	return []Suggestion{{PackageID: pkg.ID, Host: host, Reason: "dns_observed"}}
}

// TargetSeeds contains only explicit user groups; the network has no service cards.
func (d Document) TargetSeeds() []TargetSeed {
	var out []TargetSeed
	for _, p := range d.EnabledPackages() {
		if p.PathForce == "direct" || p.IsCanary() {
			continue
		}
		label := p.Label
		if label == "" {
			label = p.ID
		}
		out = append(out, TargetSeed{ID: p.ID, Label: label})
	}
	return out
}

func (d Document) PackageIDForHost(host string) string {
	if p, ok := d.MatchPackage(host); ok {
		return p.ID
	}
	return ""
}
