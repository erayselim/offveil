# Revoked ruleset signing keys

These public keys must **not** be used to sign new `active.json` files.

Git history may still contain matching private material. Rotation means a
new public key is embedded in `channel.json` and `DefaultPublicKeyHex`.

| Hex (Ed25519 public) | Status | Notes |
|----------------------|--------|--------|
| `c36e183968a6cf5423400329b5878af0c3afa028d7b7d564071d625ecd466d7a` | **revoked** | Former `dev-signing.key` (was committed). Do not trust new rulesets signed by this key. |

Production signing: GitHub Actions secret `OFFVEIL_RULESET_PRIVATE_KEY` only.
Public embed: `ruleset/keys/public.key` + `channel.json`.
