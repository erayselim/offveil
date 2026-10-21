package ruleset_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
)

func TestParseBundledNetworkPolicy(t *testing.T) {
	doc, err := ruleset.ParseDocument(ruleset.BundledActive())
	if err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != ruleset.SchemaVersion || doc.Version != ruleset.MinVersion {
		t.Fatalf("unexpected policy: %+v", doc)
	}
	if len(doc.Packages) != 0 || len(doc.EnabledPackages()) != 0 || len(doc.TargetSeeds()) != 0 {
		t.Fatal("default policy contains destination groups")
	}
	if len(doc.Network.Routes) != 0 || len(doc.TunnelDomains()) != 0 || len(doc.DirectDomains()) != 0 || len(doc.ProtectedDomains()) != 0 {
		t.Fatal("default policy contains routing exceptions")
	}
	if !reflect.DeepEqual(doc.ProbeHosts(), ruleset.DefaultControlHosts()) || len(doc.CanaryProbeHosts()) != 0 {
		t.Fatalf("controls: %v", doc.ProbeHosts())
	}
	if !reflect.DeepEqual(doc.ResolveHosts(), doc.ProbeHosts()) {
		t.Fatalf("resolve seeds: %v", doc.ResolveHosts())
	}
	hosts := doc.ProbeHosts()
	hosts[0] = "changed.test"
	if doc.ProbeHosts()[0] == "changed.test" {
		t.Fatal("caller mutated document controls")
	}
}

func TestParseRejectsObsoleteAndInvalidNetworkPolicies(t *testing.T) {
	for name, raw := range map[string]string{
		"obsolete schema":          `{"version":6,"packages":[{"id":"old","default_enabled":true,"domains":["old.test"]}]}`,
		"obsolete version":         `{"schema_version":2,"version":6,"network":{"control_hosts":["one.test","two.test"]}}`,
		"missing controls":         `{"schema_version":2,"version":7,"packages":[]}`,
		"restored packages":        `{"schema_version":2,"version":7,"network":{"control_hosts":["one.test","two.test"]},"packages":[{"id":"obsolete","default_enabled":true,"domains":["obsolete.test"]}]}`,
		"duplicate controls":       `{"schema_version":2,"version":7,"network":{"control_hosts":["ONE.test","one.test"]}}`,
		"url as control":           `{"schema_version":2,"version":7,"network":{"control_hosts":["https://one.test","two.test"]}}`,
		"unknown route":            `{"schema_version":2,"version":7,"network":{"control_hosts":["one.test","two.test"],"routes":[{"domains":["user.test"],"path":"unknown"}]}}`,
		"unsupported tunnel route": `{"schema_version":2,"version":7,"network":{"control_hosts":["one.test","two.test"],"routes":[{"domains":["user.test"],"path":"tunnel"}]}}`,
		"unsupported desync route": `{"schema_version":2,"version":7,"network":{"control_hosts":["one.test","two.test"],"routes":[{"domains":["user.test"],"path":"desync"}]}}`,
		"empty route":              `{"schema_version":2,"version":7,"network":{"control_hosts":["one.test","two.test"],"routes":[{"path":"direct"}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ruleset.ParseDocument([]byte(raw)); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestExplicitRoutesAndControlsAreIndependent(t *testing.T) {
	doc, err := ruleset.ParseDocument([]byte(`{"schema_version":2,"version":7,"network":{"control_hosts":["one.test","two.test","three.test"],"routes":[{"domains":["EXACT.user.test"],"domain_suffix":[".local.test"],"path":"direct"}]},"packages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(doc.DirectDomains(), []string{"exact.user.test", "local.test"}) {
		t.Fatalf("direct: %v", doc.DirectDomains())
	}
	if len(doc.Network.Routes) != 1 || !reflect.DeepEqual(doc.Network.Routes[0].Domains, []string{"exact.user.test"}) || !reflect.DeepEqual(doc.Network.Routes[0].DomainSuffix, []string{"local.test"}) {
		t.Fatalf("exact and suffix route boundaries were lost: %+v", doc.Network.Routes)
	}
	if !reflect.DeepEqual(doc.ProbeHosts(), []string{"one.test", "two.test", "three.test"}) {
		t.Fatalf("routing destination became health control: %v", doc.ProbeHosts())
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := ruleset.BundledActive()
	sig := ruleset.Sign(priv, raw)
	if err := ruleset.Verify(pub, raw, sig); err != nil {
		t.Fatal(err)
	}
	if err := ruleset.Verify(pub, raw, "AAAA"); err == nil {
		t.Fatal("invalid signature accepted")
	}
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)-2] ^= 0xff
	if err := ruleset.Verify(pub, tampered, sig); err == nil {
		t.Fatal("tampered policy accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func updateClient(t *testing.T, body []byte, priv ed25519.PrivateKey) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var content string
		switch req.URL.Path {
		case "/active.json":
			content = string(body)
		case "/active.json.sig":
			content = ruleset.Sign(priv, body) + "\n"
		default:
			t.Errorf("unexpected update path %s", req.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(content)), Header: make(http.Header), Request: req}, nil
	})}
}

func TestRemoteUpdate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ruleset.ParseDocument(ruleset.BundledActive())
	if err != nil {
		t.Fatal(err)
	}
	doc.Version = 99
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	t.Setenv("OFFVEIL_RULESET_CACHE", cache)
	t.Setenv("OFFVEIL_RULESET_URL", "https://updates.example.test")
	snap, err := ruleset.Load(context.Background(), ruleset.LoadOptions{PublicKeyHex: hex.EncodeToString(pub), HTTPClient: updateClient(t, body, priv)})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Doc.Version != 99 || snap.Source != "remote" {
		t.Fatalf("remote update was not selected: %+v", snap)
	}
	if _, err := os.Stat(filepath.Join(cache, "active.json")); err != nil {
		t.Fatal(err)
	}
	cached, err := ruleset.Load(context.Background(), ruleset.LoadOptions{PublicKeyHex: hex.EncodeToString(pub), SkipRemote: true})
	if err != nil {
		t.Fatal(err)
	}
	if cached.Source != "cache" || cached.Doc.Version != 99 {
		t.Fatalf("verified cache unavailable: %+v", cached)
	}
}

func TestSignedObsoletePolicyCannotReturnThroughAnySource(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)
	for name, raw := range map[string]string{
		"schema1":          `{"version":6,"packages":[{"id":"obsolete","default_enabled":true,"domains":["obsolete.test"]}]}`,
		"version6":         `{"schema_version":2,"version":6,"network":{"control_hosts":["one.test","two.test"]},"packages":[]}`,
		"schema2 packages": `{"schema_version":2,"version":99,"network":{"control_hosts":["one.test","two.test"]},"packages":[{"id":"obsolete","default_enabled":true,"domains":["obsolete.test"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			cache := t.TempDir()
			body := []byte(raw)
			jp := filepath.Join(cache, "active.json")
			sp := jp + ".sig"
			if err := os.WriteFile(jp, body, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sp, []byte(ruleset.Sign(priv, body)), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ruleset.LoadFile(jp, sp, pubHex, true); err == nil {
				t.Fatal("signed obsolete local policy accepted")
			}
			if _, err := ruleset.LoadFile(jp, "", pubHex, false); err == nil {
				t.Fatal("unsigned obsolete local policy accepted")
			}
			t.Setenv("OFFVEIL_RULESET_CACHE", cache)
			t.Setenv("OFFVEIL_RULESET_URL", "https://updates.example.test")
			for _, remote := range []bool{false, true} {
				snap, err := ruleset.Load(context.Background(), ruleset.LoadOptions{PublicKeyHex: pubHex, SkipRemote: !remote, HTTPClient: updateClient(t, body, priv)})
				if err != nil {
					t.Fatal(err)
				}
				if snap.Doc.SchemaVersion != 2 || snap.Doc.Version < 7 || snap.Source == "cache" || snap.Source == "remote" || len(snap.Doc.Packages) > 0 {
					t.Fatalf("obsolete policy restored: %+v", snap)
				}
			}
		})
	}
}

func TestLoadSkipRemoteAndChannelMinimum(t *testing.T) {
	t.Setenv("OFFVEIL_RULESET_CACHE", t.TempDir())
	snap, err := ruleset.Load(context.Background(), ruleset.LoadOptions{SkipRemote: true})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Doc.SchemaVersion != 2 || snap.Doc.Version < 7 {
		t.Fatalf("unexpected policy: %+v", snap)
	}
	ch, err := ruleset.ParseChannel(ruleset.BundledChannel())
	if err != nil {
		t.Fatal(err)
	}
	if ch.PublicKeyHex != ruleset.DefaultPublicKeyHex || ch.MinRulesetVersion < 7 {
		t.Fatalf("invalid channel: %+v", ch)
	}
	if _, err := ruleset.ParsePublicKeyHex(ch.PublicKeyHex); err != nil {
		t.Fatal(err)
	}
}

func TestSourceAndEmbeddedPolicyMatch(t *testing.T) {
	jp := filepath.Join("..", "..", "..", "ruleset", "active.json")
	raw, err := os.ReadFile(jp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, ruleset.BundledActive()) {
		t.Fatal("repository source and embedded policy differ")
	}
	sig, err := os.ReadFile(jp + ".sig")
	if os.IsNotExist(err) {
		t.Log("release CI supplies the signature for the current source")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := ruleset.VerifyHexKey(ruleset.DefaultPublicKeyHex, raw, string(sig)); err != nil {
		t.Fatalf("source signature: %v", err)
	}
}
