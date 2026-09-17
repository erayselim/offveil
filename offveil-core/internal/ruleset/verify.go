package ruleset

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// DefaultPublicKeyHex is the bootstrap channel public key (ruleset/keys/public.key).
// Keep in sync with ruleset/channel.json. Previous committed key: see keys/REVOKED.md.
const DefaultPublicKeyHex = "cbec8bde20e58e0f31d8c6757d476c72b29b33d9665ceb0c81f1f21087d51fcc"

// ParsePublicKeyHex decodes a 32-byte Ed25519 public key from hex.
func ParsePublicKeyHex(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("public key hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key: want %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKeyHex decodes a 64-byte Ed25519 private key from hex.
func ParsePrivateKeyHex(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimSpace(s)
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("private key hex: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key: want %d bytes, got %d", ed25519.PrivateKeySize, len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// Sign returns base64(Ed25519(raw)) for the given private key.
func Sign(priv ed25519.PrivateKey, raw []byte) string {
	sig := ed25519.Sign(priv, raw)
	return base64.StdEncoding.EncodeToString(sig)
}

// Verify checks a base64 signature against raw file bytes.
func Verify(pub ed25519.PublicKey, raw []byte, sigB64 string) error {
	sigB64 = strings.TrimSpace(sigB64)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("signature base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature: want %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(pub, raw, sig) {
		return fmt.Errorf("signature: verification failed")
	}
	return nil
}

// VerifyHexKey verifies using a hex-encoded public key.
// LF and CRLF bodies are both accepted: Windows working trees often sign
// CRLF while git stores LF.
func VerifyHexKey(pubHex string, raw []byte, sigB64 string) error {
	pub, err := ParsePublicKeyHex(pubHex)
	if err != nil {
		return err
	}
	err = Verify(pub, raw, sigB64)
	if err == nil {
		return nil
	}
	lf := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	crlf := bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
	for _, cand := range [][]byte{lf, crlf} {
		if bytes.Equal(cand, raw) {
			continue
		}
		if Verify(pub, cand, sigB64) == nil {
			return nil
		}
	}
	return err
}
