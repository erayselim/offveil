**İndir:** [Windows 64-bit]({{DOWNLOAD_BASE}}/offveil_{{VERSION}}_x64-setup.exe) · [Mac — M1 ve sonrası]({{DOWNLOAD_BASE}}/offveil_{{VERSION}}_aarch64.dmg)

**Beta sürümü.** Koruma yeniden tasarlandı. Kararlı sürüm kullananlara güncelleme olarak sunulmaz; kurmak için yukarıdaki bağlantıları kullanın. Beta'yı kurduktan sonra sonraki beta'lar ve kararlı sürüm uygulama içinden gelir.

Önceki beta, tüm trafiği tünelden geçirmeye çalışıyordu. Bu bazı hatlarda yavaşlığa, bağlantı kopmalarına ve koruma açılamamasına yol açtı. Bu sürümde yöntem tersine döndü: koruma önce ağınızı ölçüyor, sadece gerekeni açıyor.

- Engelli adresler doğrudan açılıyorsa yalnızca DNS koruması çalışır. Sanal ağ kartı ve vekil açılmaz.
- Ağ engelliyorsa web trafiği (IPv4) yerelde aşılır. Engelsiz sitelere dokunulmaz, bu yüzden gereksiz yavaşlama olmaz.
- İndirmeler, oyunlar, QUIC ve UDP olduğu gibi doğrudan gider. Oyun mağazaları, sistem güncellemeleri ve bankalar hiç karışılmaz.
- Tünel yalnızca yerel aşmanın açamadığı hizmet için devreye girer. WARP için birkaç adres ve port sırayla denenir.
- DNS, CDN'lerin size yakın sunucu vermesini sağlayan sağlayıcıyla başlar.
- Windows'ta ağ kartının hazır olması için beklenen süre uzatıldı. Sanal ağ kartı kurulamasa bile DNS koruması açık kalır ve ekranda **Sınırlı Koruma** görünür.
- **Bozuldu** artık yalnızca DNS durduğunda ya da kurtarma tükendiğinde görünür. İnternet yoksa **Bağlantı Yok** yazar. Yenile'ye basınca Bozuldu görünmez.
- Mac'te destek dosyası yönetici izni olmadan da eksiksiz oluşur. Dosyaya ağın engel durumu, açık katmanlar ve kısa bir hız ölçümü eklendi.

Sorun yaşarsanız lütfen **Ayarlar → Destek dosyası kaydet** ile rapor paylaşın; bu sürümün asıl amacı farklı hatlarda denenmek. Özellikle Superonline, Kablonet ve Türk Telekom geri bildirimi önemli.

Windows'ta SmartScreen, Mac'te geliştirici doğrulama uyarısı çıkabilir. [Windows](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/antivirus.md) · [Mac kurulumu](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/beta-mac.md)

İndirmelerin doğrulama bilgileri `SHA256SUMS.txt` içinde. [Ağ mimarisi](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/network-architecture.md) · [Ağ tanılama](https://github.com/erayselim/offveil/blob/{{TAG}}/docs/network-diagnostics.md)
