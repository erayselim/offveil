Protection used to follow a short site list. It now applies while the switch is on: Windows DNS goes through local DoH, and HTTPS (TCP/443) uses DPI desync by default. You do not add domains by hand.

UDP stays on your ISP path, so games keep their ping. Steam, Riot, Epic, and Faceit store/launcher HTTPS are excluded from desync. Discord and IMVU still get extra handling when the path is dropped.

This is not a VPN and not a full-tunnel. It will not open every site on every ISP. Crisis-day throttling of large platforms is still out of this build.

Download `offveil_*_x64-setup.exe` from Assets. Compare its SHA-256 with `SHA256SUMS.txt` on this release.

If Windows shows **Windows protected your PC**, click More info, then Run anyway.

If it does not work: Settings → Save a support file, and attach that file to your report.
