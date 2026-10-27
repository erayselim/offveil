# Network policy

`active.json` version 8 uses schema 3. It is the same file as the embedded copy
in `offveil-core/internal/ruleset/bundled/`.

| Section | Meaning |
| --- | --- |
| `network.control_hosts` | Neutral TLS checks. They tell "no internet" apart from filtering. At least two. |
| `canaries` | Destination groups that are filtered together. `probe_hosts` are measured, `domain_suffix` follows the group's path. |
| `exclude` | Suffixes that always go direct: game stores, OS updates, banks, government sites. |
| `strategies` | Extra ByeDPI candidates. `platform` is `windows`, `darwin` or empty. |
| `poison_ips` | Extra DNS censorship answers, on top of the built-in list. |
| `network.routes` | Optional explicit `direct` exceptions. Other paths are rejected. |

Canary `kind`:

- `persistent`: filtered on most lines. If these open directly, the network has
  no SNI filtering and offveil keeps only the DNS layer.
- `crisis`: filtered on specific days. Checked less often; a failure turns on
  the TCP layer and, if needed, the tunnel for that group only.

Every probe host must sit under one of its group's suffixes. Strategy arguments
are checked against the engine's flag allowlist before use; file paths, PID
files and listen options are refused.

`packages` must be empty. Nonempty legacy lists are rejected.

## Signed updates

- `channel.json` and its embedded copy require ruleset version 8 or later.
- Cache, local-file and remote documents must use schema 3. A valid signature on
  an older schema cannot restore an obsolete policy.
- Remote and cached files need a valid Ed25519 signature. Failed validation keeps
  the accepted local policy or falls back to the embedded one.
- Release CI creates `active.json.sig` with its private signing secret. No
  development key or placeholder signature is committed.
- `keys/` holds the public verification key and key history.

`OFFVEIL_RULESET_URL` overrides the update URL for controlled tests. Signature
verification stays on for downloaded and cached updates.
