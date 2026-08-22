package tunnel

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyPair is a WireGuard / Reality X25519 key pair (base64 std encoding).
type KeyPair struct {
	Private string
	Public  string
}

// GenerateKeyPair creates a new X25519 key pair for WARP registration.
func GenerateKeyPair() (KeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return KeyPair{}, err
	}
	// Clamp per X25519 / WireGuard.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		Private: base64.StdEncoding.EncodeToString(priv[:]),
		Public:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// ReservedFromClientID decodes WARP client_id into WireGuard reserved bytes.
// Cloudflare requires these for traffic to flow after handshake.
func ReservedFromClientID(clientID string) ([3]byte, error) {
	var out [3]byte
	if clientID == "" {
		return out, fmt.Errorf("empty client_id")
	}
	raw, err := base64.StdEncoding.DecodeString(clientID)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(clientID)
		if err != nil {
			return out, fmt.Errorf("client_id decode: %w", err)
		}
	}
	if len(raw) < 3 {
		return out, fmt.Errorf("client_id too short (%d)", len(raw))
	}
	copy(out[:], raw[:3])
	return out, nil
}
