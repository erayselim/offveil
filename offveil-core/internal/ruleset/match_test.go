package ruleset_test

import (
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
)

func TestIMVUPackageAndExpand(t *testing.T) {
	doc, err := ruleset.ParseDocument(ruleset.BundledActive())
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version < 5 {
		t.Fatalf("want ruleset v5+, got %d", doc.Version)
	}

	pkg, ok := doc.MatchPackage("webasset-akm.imvu.com")
	if !ok || pkg.ID != "imvu" {
		t.Fatalf("MatchPackage CDN: ok=%v pkg=%+v", ok, pkg)
	}
	if _, ok := doc.MatchPackage("de.secure.imvu.com"); !ok {
		t.Fatal("suffix should cover de.secure.imvu.com")
	}
	for _, h := range []string{"steampowered.com", "riotgames.com", "epicgames.com", "faceit.com"} {
		if _, ok := doc.MatchPackage(h); ok {
			t.Fatalf("direct-games must not MatchPackage for expand: %s", h)
		}
	}

	rh := doc.ResolveHosts()
	for _, want := range []string{"secure.imvu.com", "webasset-akm.imvu.com", "userimages-akm.imvu.com", "gateway.discord.gg"} {
		if !contains(rh, want) {
			t.Fatalf("ResolveHosts missing %s: %v", want, rh)
		}
	}

	already := map[string]struct{}{
		"secure.imvu.com": {},
	}
	sug := doc.ExpandForHost("secure.imvu.com", already)
	if len(sug) == 0 {
		t.Fatal("expected CDN sibling suggestions for half-load expand")
	}
	var sawAsset bool
	for _, s := range sug {
		if s.PackageID != "imvu" {
			t.Fatalf("suggestion package %s", s.PackageID)
		}
		if s.Host == "webasset-akm.imvu.com" || s.Host == "userimages-akm.imvu.com" {
			sawAsset = true
			if s.Reason != "cdn_sibling" && s.Reason != "resolve_seed" {
				t.Fatalf("reason %s for %s", s.Reason, s.Host)
			}
		}
		if s.Host == "secure.imvu.com" {
			t.Fatal("already-routed secure.imvu.com should be skipped")
		}
	}
	if !sawAsset {
		t.Fatalf("expected asset CDN sibling, got %+v", sug)
	}

	// Dynamic host under .imvu.com not in resolve seeds → dns_observed + siblings.
	already2 := map[string]struct{}{}
	for _, h := range doc.ResolveHosts() {
		already2[h] = struct{}{}
	}
	dyn := doc.ExpandForHost("avatars.imvu.com", already2)
	foundObs := false
	for _, s := range dyn {
		if s.Host == "avatars.imvu.com" && s.Reason == "dns_observed" {
			foundObs = true
		}
	}
	if !foundObs {
		t.Fatalf("expected dns_observed for avatars.imvu.com, got %+v", dyn)
	}

	seeds := doc.TargetSeeds()
	if len(seeds) < 2 || seeds[0].ID != "discord" {
		t.Fatalf("TargetSeeds: %+v", seeds)
	}
	var sawIMVU bool
	for _, s := range seeds {
		if s.ID == "imvu" {
			sawIMVU = true
		}
	}
	if !sawIMVU {
		t.Fatal("TargetSeeds missing imvu")
	}
	for _, s := range seeds {
		if s.ID == "canary" {
			t.Fatal("TargetSeeds must skip canary")
		}
	}
}

func TestCanaryPackage(t *testing.T) {
	doc, err := ruleset.ParseDocument(ruleset.BundledActive())
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := doc.MatchPackage("www.youtube.com")
	if !ok || !pkg.IsCanary() {
		t.Fatalf("youtube canary: ok=%v pkg=%+v", ok, pkg)
	}
	if sug := doc.ExpandForHost("www.youtube.com", nil); len(sug) != 0 {
		t.Fatalf("canary expand: %+v", sug)
	}
	if contains(doc.TunnelDomains(), "youtube.com") {
		t.Fatal("TunnelDomains must not include canary suffixes by default")
	}
	if contains(doc.ResolveHosts(), "www.youtube.com") {
		t.Fatal("ResolveHosts must skip canary")
	}
	if contains(doc.ProbeHosts(), "www.youtube.com") {
		t.Fatal("ProbeHosts must skip canary")
	}
	if !contains(doc.CanaryProbeHosts(), "x.com") {
		t.Fatal("CanaryProbeHosts missing x.com")
	}
	for _, h := range []string{"steampowered.com", "riotgames.com"} {
		if contains(doc.CanaryProbeHosts(), h) {
			t.Fatalf("games leaked into canary probe: %s", h)
		}
	}
}

func TestTunnelDomainsIncludeIMVU(t *testing.T) {
	doc, err := ruleset.ParseDocument(ruleset.BundledActive())
	if err != nil {
		t.Fatal(err)
	}
	tun := doc.TunnelDomains()
	if !contains(tun, "imvu.com") || !contains(tun, "secure.imvu.com") {
		t.Fatalf("tunnel missing imvu: %v", tun)
	}
}
