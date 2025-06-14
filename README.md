# offveil - DNS & DPI Aracı

![offveil](offveil.png)
*“**offveil**”, İngilizce “**off**” (kaldırmak, devre dışı bırakmak) ve “**veil**” (örtü, perde, gizleyici katman) kelimelerinin birleşimidir. Uygulamanın amacı da tam olarak budur: kasten konulmuş dijital engelleri, gizli veya görünmez erişim kısıtlarını sessizce devre dışı bırakmak. **offveil**, perdeyi aralayan sade ama etkili bir çözüm sunar.*


## 📋 Teknik ve Güvenlik Bilgisi

- **offveil**, Türkiye'deki internet erişim engellerini aşmak için geliştirilmiş, tamamen açık kaynaklı ve ücretsiz bir masaüstü uygulamasıdır.
- Uygulama, bilgisayarınızda hiçbir zararlı işlem yapmaz, kişisel verilerinizi toplamaz veya üçüncü şahıslarla paylaşmaz.
- Sadece, internet servis sağlayıcılarının uyguladığı DNS ve DPI (Derin Paket İnceleme) tabanlı engellemeleri aşmak için, sisteminizdeki DNS ayarlarını değiştirir ve arka planda DPI atlatıcı bir servis başlatır.
- Uygulama, ticari bir amaç gütmez ve tamamen topluluk yararına geliştirilmiştir.
- Kaynak kodlarını dilediğiniz gibi inceleyebilir, güvenle kullanabilirsiniz.

---

## ⚠️ Antivirüs Uyarıları Hakkında

Bazı antivirüs programları veya VirusTotal gibi siteler, yeni ve sistem ayarlarını değiştiren uygulamaları "yanlış pozitif" olarak zararlıymış gibi gösterebilir. **offveil**, açık kaynaklıdır ve hiçbir zararlı yazılım içermez. Kodlarını inceleyebilir, dilediğiniz gibi denetleyebilirsiniz. Bu tür uyarılar, uygulamanın yeni olması ve sistem üzerinde değişiklik yapmasından kaynaklanır.

---

## 🚀 Kullanım

- **Önerilen DNS & DPI Ayarlarını Uygula:**
    - Çoğu kullanıcı için tek tıkla tüm engelleri aşmak için yeterlidir.
- **Alternatif DNS & DPI Seçenekleri:**
    - Farklı internet servis sağlayıcıları için özel olarak hazırlanmış alternatiflerdir.
    - Örneğin, **Superonline** kullanıcıları için "Alternatif 1" kullanılabilir.
    - Diğer alternatifler, bazı özel durumlarda veya farklı sağlayıcılarda işe yarayabilir.
- **DNS Değiştir:**
    - Sadece DNS ayarlarını değiştirir. (Uygulamada kullanılan DNS: `1.1.1.1` ve `2606:4700:4700::1111`)
- **DPI Etkinleştir:**
    - Sadece DPI atlatıcı servisi başlatır. (GoodbyeDPI'ın aksine, Yandex DNS sunucuları değil, Cloudflare sunucularını kullanılır)
- **Tüm Ayarları Sıfırla:**
    - Tüm değişiklikleri geri alır, sisteminizi eski haline döndürür.

> **Not:** Uygulama, Windows üzerinde yönetici yetkisiyle çalışır. İşlemler sırasında arayüzdeki bilgilendirme mesajlarını takip edebilirsiniz.

---

## 💡 Sıkça Sorulanlar

### Uygulama güvenli mi?
Evet. **offveil** tamamen açık kaynaklıdır, kodları şeffaftır ve hiçbir şekilde kişisel verinizi toplamaz veya paylaşmaz. Sadece sisteminizdeki DNS ve ağ servislerini yönetir.

### Neden antivirüs uyarısı alıyorum?
Yeni ve sistem ayarlarını değiştiren uygulamalar, bazı antivirüsler tarafından otomatik olarak "şüpheli" olarak işaretlenebilir. Bu, uygulamanın zararlı olduğu anlamına gelmez.

### Hangi DNS ve DPI ayarları kullanılıyor?
Uygulamada, erişim engellerini aşmak için özel olarak seçilmiş DNS adresleri (`1.1.1.1` ve `2606:4700:4700::1111`) ve DPI atlatıcı servis parametreleri kullanılmaktadır. Alternatifler, farklı sağlayıcılar için optimize edilmiştir.

### Hangi internet sağlayıcılarında çalışır?
Çoğu kullanıcı için "Önerilen DNS & DPI Ayarlarını Uygula" seçeneği yeterlidir. Superonline gibi bazı sağlayıcılarda ise "Alternatif 1" daha iyi sonuç verebilir.

---

## 🔒 Açık Kaynak ve Güven

- **offveil tamamen açık kaynaklıdır**.
- Hiçbir şekilde kar amacı gütmez, topluluk yararına geliştirilmiştir.
- Her türlü katkı, öneri ve geri bildirime açığız.

---

## 🛠️ Kullanılan Teknolojiler

- **Python:** Uygulamanın ana dili.
- **Flet:** Masaüstü arayüzü için.
- **subprocess, os, sys:** Sistem ve ağ ayarlarını değiştirmek için.
> Ek bağımlılıklar `requirements.txt` dosyasında listelenmiştir.

---

## 📜 Krediler

- [ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) (DPI atlatıcı çekirdek)
- [cagritaskn/GoodbyeDPI-Turkey](https://github.com/cagritaskn/GoodbyeDPI-Turkey) (Türkiye için optimize edilmiş parametreler)
 **Not:** **offveil**, GoodbyeDPI ve GoodbyeDPI-Turkey'den farklı olarak, Yandex sunucuları (`77.88.8.8` ve `2a02:6b8::feed:0ff`) yerine, daha güvenilir ve hızlı olan Cloudflare (`1.1.1.1` ve `2606:4700:4700::1111`) sunucularını kullanır.

---

## 👨‍💻 Gelişmiş Kullanıcılar İçin: Depoyu Klonlamak

> Bu bölüm, uygulamayı kaynak koddan çalıştırmak veya geliştirmek isteyen ileri düzey kullanıcılar içindir.

```bash
git clone https://github.com/erayselim/offveil.git
cd offveil
```
Tüm bağımlılıkları yüklemek için:
```bash
python -m pip install -r requirements.txt
```

---

Her türlü soru, öneri veya hata bildirimi için [GitHub Issues](https://github.com/erayselim/offveil/issues) bölümünü kullanabilirsiniz. 
