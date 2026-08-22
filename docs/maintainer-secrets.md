# Maintainer secrets

Do not commit private keys. Local copies live under gitignored `.secrets/`.

| GitHub Actions secret | |
|----------------------|--|
| `OFFVEIL_RULESET_PRIVATE_KEY` | 64-byte hex Ed25519 (one line). Public: `ruleset/keys/public.key` |
| `TAURI_SIGNING_PRIVATE_KEY` | Tauri updater minisign private key |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Password used when generating the key (may be empty) |

The repo should stay public so artifact attestation stays free.

After clone, if `.secrets/ruleset-prod.key` exists:

```powershell
$env:OFFVEIL_RULESET_PRIVATE_KEY = (Get-Content .secrets\ruleset-prod.key -Raw).Trim()
go run .\offveil-core\cmd\ruleset-sign\ --in .\ruleset\active.json --out .\ruleset\active.json.sig
```

Updater key:

```powershell
cd offveil-ui
npx tauri signer generate -w ..\.secrets\tauri.key
```

Put the printed **public** key in `offveil-ui/src-tauri/tauri.conf.json`
under `plugins.updater.pubkey`. If you used `-p`, the password file is
`.secrets/tauri.password` (gitignored).
