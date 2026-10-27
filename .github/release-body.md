**Download / İndir:** [Windows 64-bit]({{DOWNLOAD_BASE}}/offveil_{{VERSION}}_x64-setup.exe) · [Mac — Apple Silicon]({{DOWNLOAD_BASE}}/offveil_{{VERSION}}_aarch64.dmg)

**Beta — test release / test sürümü.** Stable installs are not offered this build by the updater. Install it by hand; after that it updates within the beta channel.

- Protection measures the network first. If filtered destinations open directly, only the local DNS layer runs: no TUN, no proxy.
- When the network filters, IPv4 web traffic goes through local desync, which leaves unfiltered connections untouched. UDP, QUIC, game stores, OS updates and banks stay direct.
- Strategy search now targets destinations that are actually filtered, not neutral hosts.
- A tunnel is used only for a group that desync cannot open. WARP endpoints and ports are tried in turn; group paths switch without rebuilding the adapter.
- DNS prefers resolvers that keep CDN answers local. If the TCP layer cannot start, DNS protection stays on and the app shows Limited Protection.
- Broken is shown only when the resolver stops or recovery gives up. No internet shows as No Connection.
- macOS support files include the full report without administrator access. Exports add the filtering verdict, active layers and a short speed sample.

Koruma önce ağı ölçer. Engelli adresler doğrudan açılıyorsa yalnızca yerel DNS çalışır. Engel varsa IPv4 web trafiği yerelde aşılır; engelsiz bağlantılara dokunulmaz, UDP, QUIC, oyun ve güncelleme trafiği doğrudan gider. Tünel yalnızca yerel aşmanın açamadığı hizmet için kullanılır. TCP katmanı kurulamazsa DNS koruması açık kalır.

Windows SmartScreen and macOS developer verification may show a warning. [Windows guidance](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/antivirus.md) · [Mac installation](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/beta-mac.md)

If something fails, share **Settings → Save support file / Ayarlar → Destek dosyası kaydet**. Verify downloads with `SHA256SUMS.txt`. [Architecture](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/network-architecture.md) · [Network diagnostics](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/network-diagnostics.md). Source, build workflows and third-party notices are public in this repository.
