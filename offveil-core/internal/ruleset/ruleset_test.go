package ruleset_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
)

func TestParseBundled(t *testing.T) {
	doc, err := ruleset.ParseDocument(ruleset.BundledActive())
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version < 6 {
		t.Fatalf("version %d", doc.Version)
	}
	tun := doc.TunnelDomains()
	if !contains(tun, "discord.com") || !contains(tun, "discord.gg") || !contains(tun, "discord.media") {
		t.Fatalf("tunnel domains incomplete: %v", tun)
	}
	if !contains(tun, "imvu.com") {
		t.Fatalf("tunnel missing imvu: %v", tun)
	}
	dir := doc.DirectDomains()
	for _, want := range []string{"steampowered.com", "riotgames.com", "epicgames.com", "faceit.com"} {
		if !contains(dir, want) {
			t.Fatalf("direct missing %s: %v", want, dir)
		}
	}
	rh := doc.ResolveHosts()
	if !contains(rh, "gateway.discord.gg") || !contains(rh, "webasset-akm.imvu.com") {
		t.Fatalf("resolve hosts: %v", rh)
	}
	ph := doc.ProbeHosts()
	if len(ph) < 2 || ph[0] != "discord.com" {
		t.Fatalf("probe hosts: %v", ph)
	}
	if contains(ph, "www.youtube.com") {
		t.Fatalf("canary must not be in session ProbeHosts: %v", ph)
	}
	ch := doc.CanaryProbeHosts()
	if !contains(ch, "www.youtube.com") || !contains(ch, "web.telegram.org") {
		t.Fatalf("canary probe hosts: %v", ch)
	}
	for _, bad := range []string{"steampowered.com", "riotgames.com", "epicgames.com", "faceit.com"} {
		if contains(ph, bad) || contains(rh, bad) {
			t.Fatalf("exclude host leaked into probe/resolve: %s probe=%v resolve=%v", bad, ph, rh)
		}
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
		t.Fatal("expected verify fail")
	}
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)-2] ^= 0xff
	if err := ruleset.Verify(pub, tampered, sig); err == nil {
		t.Fatal("expected tamper fail")
	}
}

func TestRemoteUpdate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := ruleset.BundledActive()
	remoteBody := []byte(strings.Replace(string(body), `"version": 6`, `"version": 99`, 1))
	sig := ruleset.Sign(priv, remoteBody)

	mux := http.NewServeMux()
	mux.HandleFunc("/active.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(remoteBody)
	})
	mux.HandleFunc("/active.json.sig", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sig + "\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cache := t.TempDir()
	t.Setenv("OFFVEIL_RULESET_CACHE", cache)
	t.Setenv("OFFVEIL_RULESET_URL", srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snap, err := ruleset.Load(ctx, ruleset.LoadOptions{
		PublicKeyHex: hex.EncodeToString(pub),
	})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Doc.Version != 99 {
		t.Fatalf("want remote v99, got %d source=%s", snap.Doc.Version, snap.Source)
	}
	if snap.Source != "remote" {
		t.Fatalf("source %s", snap.Source)
	}
	cached := filepath.Join(cache, "active.json")
	if _, err := os.Stat(cached); err != nil {
		t.Fatal(err)
	}
}

func TestLoadEmbeddedSkipRemote(t *testing.T) {
	snap, err := ruleset.Load(context.Background(), ruleset.LoadOptions{SkipRemote: true})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Doc.Version < 2 {
		t.Fatalf("version %d", snap.Doc.Version)
	}
}

func TestDefaultPublicKeyMatchesChannel(t *testing.T) {
	ch, err := ruleset.ParseChannel(ruleset.BundledChannel())
	if err != nil {
		t.Fatal(err)
	}
	if ch.PublicKeyHex != ruleset.DefaultPublicKeyHex {
		t.Fatalf("channel public key != DefaultPublicKeyHex")
	}
	if _, err := ruleset.ParsePublicKeyHex(ch.PublicKeyHex); err != nil {
		t.Fatal(err)
	}
}

func TestCommittedRulesetSignature(t *testing.T) {
	paths := []string{
		filepath.Join("..", "..", "..", "ruleset", "active.json"),
		filepath.Join("..", "..", "..", "..", "ruleset", "active.json"),
	}
	var jsonPath string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			jsonPath = p
			break
		}
	}
	if jsonPath == "" {
		t.Skip("ruleset/active.json not in this checkout layout")
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(jsonPath + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	if err := ruleset.VerifyHexKey(ruleset.DefaultPublicKeyHex, raw, string(sig)); err != nil {
		t.Fatalf("committed active.json.sig: %v", err)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
