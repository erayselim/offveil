# Privacy and threat model

## Assumptions

- Attacker: ISP / national DPI, DNS poisoning, IP drop.
- Out of scope: targeted nation-state malware, physical device access,
  a malicious local administrator.

## Product surfaces

| Surface | Risk | Mitigation |
|---------|------|------------|
| Named pipe IPC `\\.\pipe\offveil-core` | Local privilege abuse | SDDL `SY` (full) + `AU` (RW); `FILE_PIPE_REJECT_REMOTE_CLIENTS`; method allowlist; 64 KiB request cap |
| LOCAL SYSTEM service `offveil-core` | Broad OS rights | Minimal RPC; Job Object kill-on-close; crash cleanup; writes under `%ProgramData%\offveil` |
| App auto-update | Supply chain | HTTPS GitHub Releases + Tauri Ed25519 pubkey; unsigned NSIS still hits SmartScreen/SAC |
| Ruleset update | Supply chain | Ed25519; unsigned/invalid remote discarded; prod private key only in CI |
| Diagnostics | PII leak | Local zip, PII scrub; no telemetry; user attaches it to an issue |
| Sidecars | GPL/MIT/Wintun terms + extra binaries | SHA-256 pin at fetch; same folder as core |

## IPC (accepted residual risk)

Any authenticated Windows user on the machine can call `start` / `stop` /
`shutdown` / `diagnostics` on the SYSTEM service. That is accepted for a
single-user home PC. It is not a multi-user kiosk design.

Remote (SMB) pipe clients are rejected.

## Privacy

- No telemetry.
- No crash minidump (SYSTEM process memory would leak PII / packet
  scraps). Panic text goes to `%ProgramData%\offveil\logs`.
- Anonymous probe sharing, if added, would be opt-in.

## Update pinning

- App: Tauri updater endpoint is `releases/latest/download/latest.json` on
  this GitHub repo. Artifacts are signed with the embedded updater pubkey.
- Ruleset: `channel.json` `base_url` + `.sig`. Rotate by putting a new key
  in the embed and the Actions secret; list the old key in
  `ruleset/keys/REVOKED.md`.
- Maintainers never upload binaries from a laptop. CI on `v*` tags only.
