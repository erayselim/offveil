Runtime files. The service creates this directory and writes:

- `warp-account.json` (Cloudflare WARP device registration)
- `sing-box-tunnel.json` (generated sing-box config, includes WG keys)
- `reality.json` (optional; only if you drop in your own credentials)

None of those belong in git. Missing WARP files are created automatically
on the next successful start.
