# Ruleset

Allowlist and DIRECT packages. Format: [docs/contracts.md](../docs/contracts.md)
section 5.

| File | |
|------|--|
| `active.json` | Discord + IMVU (legacy-cdn) + Steam/Riot/Epic/Faceit DIRECT (v5) |
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
  tunnel uses sing-box SOCKS UDP). Sniffed QUIC is dropped so the
  client falls back to TCP TLS. Raw game UDP on port 443 is not QUIC.

No IP ranges. Discord RTC hosts change often; `domain_suffix` is enough
for the selective tunnel.

## IMVU / legacy-cdn

Classic (`IMVUClient.exe`) ignores the system proxy. Domain expand records
CDN siblings when the stub sees a lookup under `.imvu.com`.

- **resolve_hosts:** `secure` / `api` / `chat` plus Akamai CDN
  (`webasset-akm`, `static-akm`, `userimages-akm`, `asset-server-akm`)
- **domain_suffix:** `.imvu.com`
- **probe_hosts:** `secure.imvu.com`

## Games (always direct)

`path_force: direct` for store and launcher HTTPS. Match UDP is not listed —
the TUN protocol split (`UDP → direct`) keeps it on the ISP path.

- Steam/Valve suffixes
- Riot: `riotgames.com`, `riotcdn.net`, `pvp.net`, `playvalorant.com`,
  `leagueoflegends.com`
- Epic: `epicgames.com`, `unrealengine.com` (no `*.akamaized.net`)
- Faceit: `faceit.com`

Skipped by `MatchPackage`, expand, and probe.

## Updates

1. Core starts from the bundled or beside-exe `active.json`.
2. `channel.json` `base_url` plus `active.json` (and `.sig`) are fetched.
3. Failed Ed25519 verify drops the download; cache or bundled stays.
4. A verified file is written under `%ProgramData%\offveil\ruleset\`.

`OFFVEIL_RULESET_URL` overrides `base_url` for tests.
