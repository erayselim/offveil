# Ruleset

Allowlist and DIRECT packages. Format: [docs/contracts.md](../docs/contracts.md)
section 5.

| File | |
|------|--|
| `active.json` | Discord + IMVU (legacy-cdn) + Steam DIRECT (v4) |
| `active.json.sig` | Ed25519 signature (base64) |
| `channel.json` | Update channel (`releases/latest/download`) |
| `keys/` | Public key. Private key is a CI secret only (`REVOKED.md`) |

## Discord

- **domains / resolve_hosts:** web, API, gateway, CDN, media, plus
  `latency.discord.media`
- **domain_suffix:** `.discord.gg` / `.discord.media` for voice and stream
  hosts that rotate
- **probe_hosts:** `discord.com`
- Voice UDP follows the TCP cascade (desync uses ByeDPI UDP ASSOCIATE,
  tunnel uses sing-box SOCKS UDP). QUIC on `UDP/443` is dropped so the
  client falls back to TCP TLS.

No IP ranges. Discord RTC hosts change often; `domain_suffix` is enough
for the selective tunnel.

## IMVU / legacy-cdn

Classic (`IMVUClient.exe`) ignores the system proxy, so selected-route
`/32`s are required.

- **resolve_hosts:** `secure` / `api` / `chat` plus Akamai CDN
  (`webasset-akm`, `static-akm`, `userimages-akm`, `asset-server-akm`)
- **domain_suffix:** `.imvu.com`
- **probe_hosts:** `secure.imvu.com`

## Updates

1. Core starts from the bundled or beside-exe `active.json`.
2. `channel.json` `base_url` plus `active.json` (and `.sig`) are fetched.
3. Failed Ed25519 verify drops the download; cache or bundled stays.
4. A verified file is written under `%ProgramData%\offveil\ruleset\`.

`OFFVEIL_RULESET_URL` overrides `base_url` for tests.
