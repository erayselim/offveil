# Ruleset signing keys

Ed25519 keypair for the default update channel (`channel.json`).

| File | Purpose |
|------|---------|
| `public.key` | Hex-encoded 32-byte public key (also in `channel.json` and embedded in core) |
| `REVOKED.md` | Former committed keys. Do not sign new rulesets with them. |

Private key is not in git. Production signing uses GitHub Actions secret
`OFFVEIL_RULESET_PRIVATE_KEY` (64-byte hex). Local copy (gitignored):
`.secrets/ruleset-prod.key`.

## Sign

From `offveil-core`:

```powershell
$env:OFFVEIL_RULESET_PRIVATE_KEY = (Get-Content ..\.secrets\ruleset-prod.key -Raw).Trim()
go run .\cmd\ruleset-sign\ --in ..\ruleset\active.json --out ..\ruleset\active.json.sig
```

Signature file: single line `base64(Ed25519(file_bytes))`.

## Verify (manual)

Core loads and verifies automatically. Unit tests generate ephemeral keys;
they do not read a private key from disk.
