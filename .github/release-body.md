## What changed

offveil now protects traffic while **Protection is enabled**, without requiring a site list.

* **DNS:** Local DoH
* **HTTPS:** DPI desync on TCP/443
* **UDP:** Stays on the ISP path for low game latency
* **Exclusions:** Steam, Riot, Epic, and FACEIT store/launcher HTTPS
* **Discord:** Gets extra handling when its normal path is dropped

offveil is **not a VPN or full-tunnel** and does not guarantee access on every ISP. Large-platform throttling is not covered by this build.

## Download

Get `offveil_*_x64-setup.exe` from **Assets** and verify it with `SHA256SUMS.txt`.

For **Windows protected your PC**: **More info → Run anyway**.

If protection fails: **Settings → Save a support file** and attach it to your report.
