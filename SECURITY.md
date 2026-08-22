# Security policy

## Supported versions

Only the latest public GitHub Release (`v1.0.0-b1` and later) is supported.

## Reporting a vulnerability

Use GitHub Security Advisories (private report):

https://github.com/erayselim/offveil/security/advisories/new

Do not open a public issue for unfixed vulnerabilities.

## Disclosure

Acknowledge reports within 7 days. Ship a fix or public advisory within
90 days unless a coordinated delay is agreed.

## What we ship

- offveil source is Apache-2.0.
- Windows installers are unsigned (no Authenticode). Trust the CI
  artifact: SHA-256 sums, GitHub artifact attestation, and Ed25519 update
  signatures. See [docs/antivirus.md](docs/antivirus.md).
- Ruleset updates are Ed25519-signed. Unsigned remotes are discarded.
- No telemetry and no crash-upload SaaS. The diagnostics zip is local and
  PII-scrubbed; the user attaches it if they want support.

## Out of scope (examples)

- SmartScreen / Smart App Control / Defender false positives on unsigned
  TUN software (expected; see antivirus docs).
- A local authenticated Windows user controlling offveil-core via IPC
  (`AU` to SYSTEM). Accepted for single-user home PCs; see
  [docs/threat-model.md](docs/threat-model.md).
