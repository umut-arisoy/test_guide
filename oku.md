# Bitdefender GravityZone Detection Test Suite

### Genel Bakış

Bu test suite, Bitdefender GravityZone'un Windows endpoint'lerde düzgün çalışıp çalışmadığını doğrulamak için geliştirilmiş **güvenli** test araçlarıdır.

**ÖNEMLİ:** Bu scriptler **SADECE TEST ORTAMINDA** kullanılmalıdır. Zararsızdır ancak antivirüs tespitlerini tetiklemek için tasarlanmıştır.

## Test Edilen Koruma Katmanları

### 1. **İmza Tabanlı Tespit**
   - EICAR standart test dosyası
   - Bilinen tehdit string'leri (mimikatz, credential dumping keywords)

### 2. **Davranışsal Analiz**
   - Hızlı çoklu dosya oluşturma (ransomware davranışı)
   - Dosya şifreleme simülasyonu
   - Dosya uzantısı değiştirme

### 3. **Script Tespiti**
   - Şüpheli PowerShell komutları (download cradle, AMSI bypass)
   - Şüpheli Python script'leri (reverse shell pattern)
   - Şüpheli Batch komutları (persistence mechanism)

### 4. **Network Koruma**
   - DNS çözümleme tespiti
   - Şüpheli domain erişimi

### 5. **Sistem Koruması**
   - WMI process spawn tespiti
   - Registry değişiklik koruması


## Kullanım

### PowerShell Versiyonu (Önerilen)

```powershell
# Execution policy ayarı (gerekirse)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Scripti çalıştır
.\calc.ps1

# Verbose mod ile
.\calc.ps1 -Verbose

# Özel log yolu ile
.\calc.ps1 -LogPath "C:\Logs\bdtest.log"
```

### Python Versiyonu

```bash
# Python 3.x gerekli
python calc.py

# veya Linux/Mac'te
python3 calc.py
```

### Batch Versiyonu

```cmd
# Sadece çift tıklayın veya
Bitdefender-Test-Suite.bat
```

## Test Sonuçlarını Anlama

### Tespit Oranları

- **%75+** = **GÜÇLÜ** - Koruma düzgün çalışıyor
- **%50-74** = **ORTA** - İnceleme gerekli, bazı koruma katmanları eksik
- **%50-** = **ZAYIF** - Acil müdahale gerekli, ciddi sorunlar var

### Beklenen Sonuçlar

| Test | Beklenen Davranış |
|------|-------------------|
| EICAR | **Mutlaka** tespit edilmeli |
| Şüpheli PowerShell | Yüksek ihtimalle tespit edilmeli |
| Hızlı dosya oluşturma | Davranışsal koruma aktifse engellemeli |
| Mimikatz string'leri | String tespiti aktifse engellemeli |
| WMI spawn | İleri koruma aktifse engellemeli |

## GravityZone Konsolunda Kontrol

Test sonrasında GravityZone konsolunda şunları kontrol edin:

1. **Dashboard** → **Security Events**
   - Son 1 saatteki event'leri filtreleyin
   - Test endpoint'inizin event'lerini görün

2. **Reports** → **Malware Detection**
   - EICAR tespit raporunu kontrol edin
   - Tarih/saat test zamanınızla eşleşmeli

3. **Endpoint Details**
   - İlgili endpoint'i seçin
   - **Security Events** sekmesine bakın
   - **Detection Status** kontrol edin

4. **Policies**
   - Real-time scanning: Enabled olmalı
   - Behavioral detection: Recommended
   - Script control: Enabled (önerilir)

## Önerilen Politika Ayarları

Test öncesi şu ayarların aktif olduğundan emin olun:

### Antimalware Policies
```
On-access scanning: Enabled
On-demand scanning: Enabled
Behavioral detection: Enabled
Script control: Enabled
Process monitoring: Enabled
```

### Advanced Threat Control
```
Exploit detection: Enabled
Ransomware mitigation: Enabled
Advanced threat detection: Enabled
```

## Güvenlik Notları

### Bu Testler:
**SADECE** tespit mekanizmalarını test eder
**Gerçek zarar vermez**
**EICAR gibi endüstri standartları kullanır**
**Antivirüs test için tasarlanmıştır**

### Bu Testler DEĞİLDİR:
Gerçek malware
Exploit tools
Penetration testing tools
Üretim sistemlerde kullanılacak

## Log Dosyaları

Her test çalışması detaylı log üretir:

**Lokasyon:** `%TEMP%\BitdefenderTest_YYYYMMDD_HHMMSS.log`

**İçerik:**
- Her test adımı
- Başarı/başarısızlık durumları
- Timestamp'ler
- Tespit detayları

### "EICAR tespit edilmedi" uyarısı
1. Real-time scanning aktif mi kontrol edin
2. Endpoint agent'ı çalışıyor mu?
3. Policy doğru atanmış mı?
4. Son update ne zaman yapıldı?

### Hiçbir test tespit edilmedi
1. Bitdefender service'leri çalışıyor mu?
   ```powershell
   Get-Service | Where-Object {$_.DisplayName -like "*Bitdefender*"}
   ```
2. Agent ile konsol arasında bağlantı var mı?
3. Policy'ler endpoint'e push edilmiş mi?
4. Exclusion listelerinde test dizinleri var mı?

### Tüm testler tespit edildi ama alert yok
1. Event log'lama aktif mi?
2. Konsol bağlantısı sağlıklı mı?
3. Reporting ayarları doğru mu?

## Ek Kaynaklar

- [Bitdefender GravityZone Dokümantasyonu](https://www.bitdefender.com/business/support/en/77209-384347-gravityzone.html)
- [EICAR Test Dosyası Hakkında](https://www.eicar.org/download-anti-malware-testfile/)
- [Windows Defender ATP için benzer testler](https://demo.wd.microsoft.com/)

---

**Son Güncelleme:** 2025
**Versiyon:** 1.0
**Uyumluluk:** Windows Server 2016+, Windows 10+, Bitdefender GravityZone
