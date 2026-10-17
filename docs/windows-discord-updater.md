# Discord web works, Windows updater stalls

Investigation date: 2026-10-18. This is a support investigation, not a confirmed
ISP-specific workaround or a claim that the reported issue has been fixed.

## Conclusion

The supplied support snapshot does not identify the failing update request.
It supports a narrower conclusion: Offveil's processes were running, but its
`discord.com` TLS probe could not establish whether Discord's Windows updater
could fetch its manifest and download its packages. The user subsequently
confirmed that Discord stalls during updating, before reaching the main client.

No routing, DNS, ByeDPI strategy, signed ruleset, or automatic fallback behavior
was changed for this report. An opt-in endpoint diagnostic was added to obtain
the missing evidence without changing normal protection behavior.

## Evidence in the supplied snapshot

| Observation | Meaning and limit |
| --- | --- |
| Windows amd64; collector and daemon report core 1.0.2 | The incident predates these diagnostic changes. |
| ASN 34984, Superonline/TELLCOM | Identifies the reported network; does not establish an ISP-wide failure. |
| Active protection; ByeDPI and sing-box up; last desync probe `ok` | The snapshot does not show a dead helper process. It does not test the updater. |
| Bundled and installed core, ByeDPI and sing-box hashes match | No evidence of a mixed installation in these three files. |
| NRPT present, stub serving, 57 queries, zero plain fallbacks/poison hits | These observations do not exclude cached answers, an alternate application resolver or an unrecognized DNS failure. |
| DNS observer saw `updates.discord.com` and `gateway.discord.gg` | Requests for these names occurred. Neither DNS observation records an HTTP response or successful download. |
| Latest Discord probe is `discord.com: open`; cascade target retains `dpi_reset -> desync` | The latest test and the retained session decision describe different things. A test while protection is active can use the protected OS route. `open` is not proof of unprotected ISP access or updater health. |
| Capture reports zero routes added | Capture is snapshot-only when sing-box owns the TUN; this counter alone does not establish missing sing-box routes. |
| UDP voice path is desync | Voice configuration does not explain an HTTPS update failure. |

The archive's SHA-256 matches its manifest. It contains a state snapshot, not a
packet capture, Discord updater error log, or per-request connection history.

## Update path and code review

The public [Windows stable x64 manifest](https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=win&arch=x64)
currently returns package URLs under `https://stable.dl2.discordapp.net/`.
These are separate requests from opening `https://discord.com/` in a browser.
Do not hard-code a particular package version or fetch an arbitrary old installer
as a connectivity test.

The current ruleset already covers `.discord.com` and `.discordapp.net`, including
the manifest host and download host. The normal TUN rules also capture public
IPv4 TCP/443 for local ByeDPI even when a hostname was not a resolve seed.
Adding `updates.discord.com` to a seed list would not establish a fix for this
incident. Relevant implementation:

- `offveil-core/internal/tunnel/config.go`: `SplitDefaultCIDRs`, `appendPolicyRules`.
- `offveil-core/internal/engine/engine.go`: session probes, `Test`, `defaultProbe`.
- `offveil-core/internal/ruleset/types.go`: `ProbeHosts`, `ProtectedDomains`.
- `ruleset/active.json`: Discord probe host and domain suffixes.

The current capture routes are IPv4 only. The local DNS stub forwards AAAA
questions, whereas the core classification probe resolves A records. If a failing
updater destination has an AAAA record and the client selects working IPv6, that
connection can bypass the IPv4 desync path. This is a conditional coverage gap,
not a diagnosis: the incident snapshot contains neither AAAA answers nor the
updater's chosen destination family. The local investigation did not obtain AAAA
addresses for the tested endpoints, so it provides no evidence that IPv6 caused
this incident. Do not disable IPv6 system-wide on this evidence.

Upstream references, checked on the investigation date:

- Discord's [Gateway documentation](https://docs.discord.com/developers/events/gateway)
  describes a separate persistent WebSocket connection; a homepage TLS handshake
  does not verify it. Gateway/voice are secondary to this user's confirmed update
  failure.
- Discord's [connection troubleshooting](https://support.discord.com/hc/en-us/articles/115001130052-Stuck-on-the-Main-Connecting-Screen)
  identifies application proxy and firewall settings as possible causes.
- Discord's [download and connection troubleshooting](https://support.discord.com/hc/en-us/articles/360033930671-Images-Not-Loading-and-Other-Connection-Errors)
  describes DNS and security software interference with downloads and updates.
  This supports checking those layers, not blaming this ISP or changing security
  settings without evidence.
- [Discord issue #8189](https://github.com/discord/discord-api-docs/issues/8189)
  reports a similar Windows updater loop with a virtual adapter and a successful
  TCP test. It is an unconfirmed user report; maintainers directed the reporter
  to client support. It supplies no validated root cause or Offveil fix.
- [Discord issue #8339](https://github.com/discord/discord-api-docs/issues/8339)
  distinguishes a legacy `/api/updates/...` route from the update service. Use
  the update service for the diagnostic, rather than treating legacy API behavior
  as the Windows client's behavior.
- The [upstream ByeDPI Windows launcher](https://raw.githubusercontent.com/hufrea/byedpi/main/dist/windows/byedpi.bat)
  uses the primary split/disorder and timeout/reset fallback already represented
  in Offveil. It does not justify changing the global Windows strategy here.
- [sing-box 1.13.14 TUN documentation](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/inbound/tun.md)
  is the version applicable to the bundled Windows helper. Its `strict_route`
  behavior has system-wide compatibility implications; enabling it speculatively
  is not a targeted updater fix.

Research used eight focused Exa searches (40 returned results), followed by
primary-source and live endpoint reads. Search hits and third-party workarounds
were not treated as verified causes.

## Added diagnostic

With a build containing this change, run as the affected desktop user while the
failure is occurring and Offveil is already enabled:

```powershell
& 'C:\Program Files\offveil\offveil-core.exe' support -check-discord -output "$env:USERPROFILE\Downloads\offveil-discord.zip"
```

This flag is new; released builds without it will reject the flag. For local
development, build `./cmd/offveil-core` and invoke that executable with the same
arguments. The command does not require installation or elevation, and works
even if the daemon is unreachable. It does not start protection or install the
development executable as a service.

Results are stored at `system.discord_connectivity` in `diagnostics.json`:

| Role | Boundary tested |
| --- | --- |
| `web` | Certificate-verified HTTPS and homepage response headers |
| `api` | HTTPS response from the public, unauthenticated Get Gateway endpoint |
| `update_manifest` | Actual Windows stable x64 manifest, valid JSON and an allowed package URL |
| `gateway` | HTTPS plus validated HTTP 101 WebSocket upgrade; no Identify/login |
| `update_download` | At most 1 KiB consumed from the manifest's full package URL using a Range request |

Each role has separate IPv4/IPv6 rows, address counts, attempt counts, failure
stage, safe error class, HTTP status when available and elapsed time. Missing
AAAA records produce `no_address`; this is not itself a service failure.
Download checks are marked `skipped_manifest_unavailable` if no usable manifest
was obtained. HTTP 403/429/5xx are preserved as statuses, not automatically
classified as censorship. Redirects are reported without following them.

The check uses the OS resolver, verified TLS and current ordinary TCP routes,
with no HTTP proxy. It does not bypass the TUN, use a sidecar SOCKS port, or claim
to establish an unprotected baseline. It does not emulate Discord's TLS library,
its process-specific firewall rules, proxy configuration, update writes or login.
A successful sample is not proof that the entire installer downloads or installs.
PTB/Canary and legacy updater flows are outside this stable x64 check.

Normal support collection is unchanged. The flag adds at most 26 seconds, uses
bounded concurrent checks, tries at most two destination IPs per role/family,
limits manifest/response reads, and cancels open connections. The only dynamic
download target allowed is HTTPS on `stable.dl2.discordapp.net` under the Windows
stable x64 distribution path; credentials, query strings, alternate ports and
non-public resolved addresses are rejected. A changed CDN/schema produces a
diagnostic failure, not a route change.

No account, token or cookie is needed. The report excludes raw errors, response
bodies/headers, resolved addresses, versioned download URLs and local file paths.
The checks contact Discord only when the flag is explicitly passed; there is no
background telemetry.

## Interpreting the next report

1. Record the exact updater message and a short, redacted updater error around
   the failure. Distinguish an HTTP/network error from package verification,
   disk-space, write-permission or local installation errors.
2. Compare `web` with `update_manifest` and `update_download`. DNS, TCP, TLS,
   certificate verification, HTTP status and partial download failure require
   different follow-up; do not label every timeout as DPI.
3. If IPv4 passes and IPv6 fails, first confirm that the updater actually chose
   IPv6. `no_address` alone cannot explain a failed IPv6 connection.
4. Fully exit Discord once, enable Offveil, then relaunch to distinguish an
   existing connection/cache from a new protected connection. Avoid deleting
   user data as an initial investigation step.
5. If possible, compare the same installation on a mobile hotspot with the same
   Offveil state. Success there narrows the network dependency without proving
   an ISP-wide issue. Retain the error timestamp and exact failed hostname.

Only a reproducible failure on the affected path justifies a routing/strategy
change or a package-specific fallback. Do not force WARP for all Discord users,
change MTU globally, disable IPv6, or disable security software based on this
snapshot.

## Validation

- Windows `go test ./...` passed, including the existing unpublished changes.
- `go test -race ./internal/support` passed for concurrent endpoint checks.
- `go vet ./internal/support ./cmd/offveil-core` passed.
- Windows and Darwin arm64 core builds succeeded (Darwin is compile validation,
  not a macOS runtime test).
- Local certificate-verified TLS fixtures cover manifest -> bounded download,
  IPv4/IPv6 selection, missing AAAA, DNS poison/private addresses, certificate
  rejection, cancellation, retry, HTTP errors, redirects, WebSocket validation
  and report redaction.
- A final live Windows CLI run produced the support ZIP and passed all five
  IPv4 roles: web/API/manifest HTTP 200, Gateway HTTP 101, and download HTTP 206
  with exactly 1,024 bytes consumed. No AAAA addresses were returned. An earlier
  independent Windows curl request received a manifest after roughly four
  seconds; this informed the longer per-attempt budget. This environment is not
  the affected customer's Superonline line.

Sandboxed runs initially could not connect to local fixture sockets or rename
some existing test files; the successful test runs used normal host access.
