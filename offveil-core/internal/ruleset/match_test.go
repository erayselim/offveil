package ruleset_test

import (
	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
	"reflect"
	"testing"
)

func TestCustomGroupMatchesOnlyConfiguredDestinations(t *testing.T) {
	doc := ruleset.Document{Network: ruleset.NetworkPolicy{ControlHosts: []string{"control-one.test", "control-two.test"}}, Packages: []ruleset.Package{
		{ID: "custom", Label: "Custom", DefaultEnabled: true, Domains: []string{"exact.user.test"}, DomainSuffix: []string{".private.test"}, ResolveHosts: []string{"asset.private.test"}},
		{ID: "bypass", DefaultEnabled: true, PathForce: "direct", DomainSuffix: []string{"bypass.test"}},
		{ID: "disabled", Domains: []string{"disabled.test"}},
	}}
	for _, host := range []string{"exact.user.test", "private.test", "nested.private.test"} {
		pkg, ok := doc.MatchPackage(host)
		if !ok || pkg.ID != "custom" {
			t.Fatalf("%s: ok=%v group=%+v", host, ok, pkg)
		}
	}
	for _, host := range []string{"unlisted.test", "bypass.test", "disabled.test", "notprivate.test"} {
		if _, ok := doc.MatchPackage(host); ok {
			t.Fatalf("unconfigured host matched: %s", host)
		}
	}
	if !reflect.DeepEqual(doc.TargetSeeds(), []ruleset.TargetSeed{{ID: "custom", Label: "Custom"}}) {
		t.Fatalf("seeds: %+v", doc.TargetSeeds())
	}
	if !reflect.DeepEqual(doc.ProbeHosts(), []string{"control-one.test", "control-two.test"}) {
		t.Fatalf("user group replaced controls: %v", doc.ProbeHosts())
	}
}

func TestObservationNeverInfersRelatedNames(t *testing.T) {
	doc := ruleset.Document{Packages: []ruleset.Package{{ID: "custom", DefaultEnabled: true, DomainSuffix: []string{"user.test"}, ResolveHosts: []string{"cdn.user.test", "asset.user.test"}}}}
	got := doc.ExpandForHost("observed.user.test", nil)
	want := []ruleset.Suggestion{{PackageID: "custom", Host: "observed.user.test", Reason: "dns_observed"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unobserved destinations inferred: %+v", got)
	}
	if got := doc.ExpandForHost("observed.user.test", map[string]struct{}{"observed.user.test": {}}); len(got) > 0 {
		t.Fatalf("duplicate observation: %+v", got)
	}
	if got := doc.ExpandForHost("unconfigured.test", nil); len(got) > 0 {
		t.Fatalf("unconfigured observation: %+v", got)
	}
}
