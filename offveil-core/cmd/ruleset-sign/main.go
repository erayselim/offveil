package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"

	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
)

func main() {
	in := flag.String("in", "", "path to ruleset JSON")
	out := flag.String("out", "", "path to write .sig (default: <in>.sig)")
	flag.Parse()
	if *in == "" {
		fmt.Fprintln(os.Stderr, "usage: ruleset-sign -in active.json [-out active.json.sig]")
		fmt.Fprintln(os.Stderr, "env: OFFVEIL_RULESET_PRIVATE_KEY=<hex 64-byte ed25519 private key>")
		os.Exit(2)
	}
	privHex := os.Getenv("OFFVEIL_RULESET_PRIVATE_KEY")
	if privHex == "" {
		fmt.Fprintln(os.Stderr, "OFFVEIL_RULESET_PRIVATE_KEY required")
		os.Exit(1)
	}
	priv, err := ruleset.ParsePrivateKeyHex(privHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key: %v\n", err)
		os.Exit(1)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}
	if _, err := ruleset.ParseDocument(raw); err != nil {
		fmt.Fprintf(os.Stderr, "ruleset: %v\n", err)
		os.Exit(1)
	}
	sig := ruleset.Sign(priv, raw)
	outPath := *out
	if outPath == "" {
		outPath = *in + ".sig"
	}
	if err := os.WriteFile(outPath, []byte(sig+"\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := ruleset.Verify(pub, raw, sig); err != nil {
		fmt.Fprintf(os.Stderr, "self-verify failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("signed %s → %s (%d bytes)\n", *in, outPath, len(raw))
}
