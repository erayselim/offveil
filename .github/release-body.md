**Download / İndir:** [Windows 64-bit]({{DOWNLOAD_BASE}}/offveil_{{VERSION}}_x64-setup.exe) · [Mac — Apple Silicon]({{DOWNLOAD_BASE}}/offveil_{{VERSION}}_aarch64.dmg)

**BETA 3 — test release / test sürümü.**

- More DPI bypass methods are tried in the background. Replacements must pass protected-connection checks before use; unsuccessful changes restore the previous method.
- Discord updater, Gateway and download endpoints receive additional TLS checks. Windows DNS, adapter startup and core service recovery are improved.
- Support reports retain more useful failure information when the service is unavailable. Existing UDP fixes remain included.

DPI aşma ve otomatik kurtarma güçlendirildi. Discord’un güncelleme ve diğer bağlantıları için ek kontroller eklendi; Windows DNS, ağ arayüzü ve servis toparlanması iyileştirildi. Destek raporları servis kapandığında da daha fazla hata bilgisini koruyor.

Testing continues across networks and devices. This beta does not claim to resolve every ISP or Discord issue. / Farklı ağ ve cihazlarda testler sürüyor; tüm ISS veya Discord sorunlarının çözüldüğü henüz doğrulanmadı.

Existing users can use **Check for Updates / Güncellemeleri kontrol et**. Updating the Mac core may require administrator approval.

Windows SmartScreen and macOS developer verification may show a warning. [Windows guidance](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/antivirus.md) · [Mac installation](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/beta-mac.md)

If something fails, share **Settings → Save support file / Ayarlar → Destek dosyası kaydet**. Verify downloads with `SHA256SUMS.txt`. Source, build workflows and third-party notices are available in this repository.
