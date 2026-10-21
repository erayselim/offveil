Runtime files. The service creates this directory and writes:

- `warp-account.json` (Cloudflare WARP device registration)
- `sing-box-*.json` (temporary gateway/provider configs; a provider config can include keys)
- `reality.json` (optional; only if you drop in your own credentials)

None of those belong in git. Missing WARP files are created automatically
on the next successful start.

Each launched process owns its temporary config and removes it on Close. Remote
providers are verified without a TUN before the shared gateway is created; no
application allowlist or process-name preset is stored here.
