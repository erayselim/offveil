**Download / İndir:** [Windows 64-bit]({{DOWNLOAD_BASE}}/offveil_{{VERSION}}_x64-setup.exe) · [Mac — Apple Silicon]({{DOWNLOAD_BASE}}/offveil_{{VERSION}}_aarch64.dmg)

**BETA 4 — test release / test sürümü.**

- Protection now routes public TCP/UDP traffic through a verified general tunnel, with IPv4/IPv6 support and no built-in application list or process-name rules.
- When no remote provider connects, the app shows **Limited Protection**: local IPv4 HTTP/TLS bypass remains available; other traffic stays direct.
- A failed site no longer blocks checks for unrelated connections. Provider switching preserves the working path until a replacement is ready, with rollback on failure.
- Support exports include general DNS/TCP/TLS/HTTP diagnostics and clearer provider/process failure facts. Old application-specific rules cannot return from cached updates.
- Core and tunnel sidecar use the patched Go toolchain; the sidecar's locked dependencies are security updated. Its source archive and build recipe are public.

Koruma, uygulama listeleri yerine genel ağ trafiğini temel alacak şekilde yenilendi. Doğrulanmış tünel TCP/UDP bağlantılarını IPv4/IPv6 üzerinden taşır. Tünel kurulamazsa **Sınırlı Koruma** görünür; yerel IPv4 HTTP/TLS aşma devrede kalırken diğer trafik doğrudan gider. Tek bir sitenin hatası diğer bağlantıların denetimini durdurmaz; sağlayıcı geçişleri ve destek raporları iyileştirildi.

This is a broad networking change. Tunnel use may change latency; testing continues on restrictive ISPs and physical devices. / Bu geniş bir ağ mimarisi değişikliğidir. Tünel kullanımı gecikmeyi değiştirebilir; katı ISS hatlarında ve gerçek cihazlarda testler sürüyor.

Existing users can use **Check for Updates / Güncellemeleri kontrol et**. Updating the Mac core may require administrator approval. Windows and Apple Silicon Macs are supported; Intel Macs are not.

Windows SmartScreen and macOS developer verification may show a warning. [Windows guidance](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/antivirus.md) · [Mac installation](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/beta-mac.md)

If something fails, share **Settings → Save support file / Ayarlar → Destek dosyası kaydet**. Verify downloads with `SHA256SUMS.txt`. [Architecture and validation](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/network-architecture.md) · [Network diagnostics](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/network-diagnostics.md). Source, build workflows and third-party notices are public in this repository.
