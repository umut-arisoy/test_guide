#!/usr/bin/env python3
"""
Detection Tests
Python Edition

"""

import os
import sys
import time
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

class Colors:
    """Terminal renkleri"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class BitdefenderTester:
    def __init__(self):
        self.test_count = 0
        self.detected_count = 0
        self.log_file = os.path.join(
            tempfile.gettempdir(),
            f"BitdefenderTest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        
    def log(self, message, level="INFO"):
        """Log mesajı yaz"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Renkli çıktı
        color_map = {
            "INFO": Colors.CYAN,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED
        }
        
        color = color_map.get(level, Colors.END)
        print(f"{color}{log_entry}{Colors.END}")
        
        # Dosyaya yaz
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + '\n')
    
    def print_banner(self):
        """Banner yazdır"""
        print("\n" + "=" * 70)
        print(f"{Colors.CYAN}  BITDEFENDER GRAVITYZONE DETECTION TEST SUITE{Colors.END}")
        print(f"{Colors.YELLOW}  Python Edition - Safe Detection Tests{Colors.END}")
        print("=" * 70 + "\n")
        
    def test_eicar(self):
        """Test 1: EICAR standart test dosyası"""
        self.test_count += 1
        print(f"\n[{self.test_count}] EICAR Standart Test Dosyası")
        self.log("EICAR test dosyası oluşturuluyor...", "INFO")
        
        try:
            eicar_string = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            eicar_path = os.path.join(tempfile.gettempdir(), 'eicar_test.com')
            
            with open(eicar_path, 'w') as f:
                f.write(eicar_string)
            
            time.sleep(2)
            
            if os.path.exists(eicar_path):
                self.log("UYARI: EICAR dosyası tespit EDİLMEDİ!", "WARNING")
                try:
                    os.remove(eicar_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: EICAR dosyası tespit edildi ve karantinaya alındı", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: EICAR yazma girişimi engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_suspicious_python_file(self):
        """Test 2: Şüpheli Python kodu"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Şüpheli Python Script Tespiti")
        self.log("Şüpheli Python script test ediliyor...", "INFO")
        
        try:
            suspicious_code = '''#!/usr/bin/env python3
# Bu bir test scriptidir - gerçekte çalıştırılmaz
# import socket, subprocess, os
# s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# s.connect(("10.0.0.1",1234))
# Reverse shell test string - DOES NOT EXECUTE
print("Bu sadece bir test - gerçek bağlantı yok")
'''
            
            script_path = os.path.join(tempfile.gettempdir(), 'suspicious_script.py')
            
            with open(script_path, 'w') as f:
                f.write(suspicious_code)
            
            time.sleep(2)
            
            if os.path.exists(script_path):
                self.log("UYARI: Şüpheli Python script tespit EDİLMEDİ", "WARNING")
                try:
                    os.remove(script_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: Şüpheli script tespit edildi", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: Script yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_rapid_file_creation(self):
        """Test 3: Hızlı dosya oluşturma (ransomware davranışı)"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Davranışsal Analiz - Hızlı Dosya Oluşturma")
        self.log("Ransomware benzeri dosya işlemleri test ediliyor...", "INFO")
        
        try:
            test_folder = os.path.join(tempfile.gettempdir(), 'rapid_file_test')
            os.makedirs(test_folder, exist_ok=True)
            
            # Hızlı dosya oluşturma
            files_created = 0
            for i in range(50):
                try:
                    file_path = os.path.join(test_folder, f'testfile_{i}.txt')
                    with open(file_path, 'w') as f:
                        f.write(f'Test file {i} - {datetime.now().timestamp()}')
                    files_created += 1
                except:
                    break
            
            time.sleep(3)
            
            if files_created == 50:
                self.log("INFO: Davranışsal koruma bu testi engellemedi", "INFO")
            else:
                self.log(f"BAŞARILI: Şüpheli dosya işlemi engellendi ({files_created}/50)", "SUCCESS")
                self.detected_count += 1
            
            # Temizlik
            try:
                shutil.rmtree(test_folder)
            except:
                pass
                
        except Exception as e:
            self.log(f"BAŞARILI: Dosya işlemi engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_suspicious_strings(self):
        """Test 4: Tehdit istihbaratı - bilinen tehdit string'leri"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Tehdit İstihbaratı - Bilinen Tehdit String'leri")
        self.log("Bilinen tehdit string'leri test ediliyor...", "INFO")
        
        try:
            threat_strings = """
# SADECE TEST - Gerçek tehdit değildir
# Bitdefender'ın string tabanlı tespitini test eder

# Credential dumping keywords
# lsass.exe sekurlsa::logonpasswords
# mimikatz kiwi privilege::debug
# procdump -ma lsass.exe lsass.dmp

# Command and Control patterns
# powershell -nop -w hidden -c "IEX..."
# cmd.exe /c certutil -decode

# Test strings only - NO ACTUAL MALWARE
"""
            
            threat_path = os.path.join(tempfile.gettempdir(), 'threat_strings_test.txt')
            
            with open(threat_path, 'w') as f:
                f.write(threat_strings)
            
            time.sleep(2)
            
            if os.path.exists(threat_path):
                self.log("INFO: String tabanlı tespit aktif değil (normal olabilir)", "INFO")
                try:
                    os.remove(threat_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: Tehdit string'i tespit edildi", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: Dosya yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_file_encryption_simulation(self):
        """Test 5: Dosya şifreleme simülasyonu"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Ransomware Davranışı - Dosya Şifreleme Simülasyonu")
        self.log("Dosya şifreleme pattern'i test ediliyor...", "INFO")
        
        try:
            test_folder = os.path.join(tempfile.gettempdir(), 'encryption_test')
            os.makedirs(test_folder, exist_ok=True)
            
            # Test dosyaları oluştur
            test_files = []
            for i in range(10):
                file_path = os.path.join(test_folder, f'document_{i}.txt')
                with open(file_path, 'w') as f:
                    f.write(f'Original content {i}')
                test_files.append(file_path)
            
            # Dosyaları "şifrele" (sadece içeriği değiştir)
            encrypted_count = 0
            for file_path in test_files:
                try:
                    # İçeriği değiştir ve uzantıyı değiştir
                    new_path = file_path + '.encrypted'
                    with open(file_path, 'r') as f:
                        content = f.read()
                    with open(new_path, 'w') as f:
                        f.write('ENCRYPTED: ' + content)
                    os.remove(file_path)
                    encrypted_count += 1
                except:
                    break
            
            time.sleep(2)
            
            if encrypted_count == 10:
                self.log("INFO: Şifreleme davranışı engellemedi", "INFO")
            else:
                self.log(f"BAŞARILI: Şifreleme davranışı engellendi ({encrypted_count}/10)", "SUCCESS")
                self.detected_count += 1
            
            # Temizlik
            try:
                shutil.rmtree(test_folder)
            except:
                pass
                
        except Exception as e:
            self.log(f"BAŞARILI: Dosya işlemi engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def print_results(self):
        """Sonuçları yazdır"""
        print("\n" + "=" * 70)
        print(f"{Colors.CYAN}  TEST SONUÇLARI{Colors.END}")
        print("=" * 70 + "\n")
        
        detection_rate = (self.detected_count / self.test_count * 100) if self.test_count > 0 else 0
        
        print(f"Toplam Test: {Colors.BOLD}{self.test_count}{Colors.END}")
        print(f"Tespit Edilen: {Colors.GREEN}{self.detected_count}{Colors.END}")
        
        rate_color = Colors.GREEN if detection_rate >= 75 else Colors.YELLOW if detection_rate >= 50 else Colors.RED
        print(f"Tespit Oranı: {rate_color}{detection_rate:.2f}%{Colors.END}\n")
        
        if detection_rate >= 75:
            self.log("SONUÇ: Bitdefender koruması GÜÇLÜ seviyede", "SUCCESS")
        elif detection_rate >= 50:
            self.log("SONUÇ: Bitdefender koruması ORTA seviyede - İnceleme önerilir", "WARNING")
        else:
            self.log("SONUÇ: Bitdefender koruması ZAYIF - Acil inceleme gerekli!", "ERROR")
        
        print(f"\nDetaylı log: {self.log_file}\n")
        print(f"{Colors.YELLOW}ÖNEMLİ NOTLAR:{Colors.END}")
        print("1. GravityZone konsolundan event'leri kontrol edin")
        print("2. Endpoint'te local log'ları inceleyin")
        print("3. Real-time koruma ayarlarını doğrulayın")
        print("4. Bu testler zararsızdır ancak üretim ortamında dikkatli kullanın\n")
        print("=" * 70 + "\n")

def main():
    """Ana fonksiyon"""
    tester = BitdefenderTester()
    
    tester.print_banner()
    tester.log("Test başlatılıyor...", "INFO")
    tester.log(f"Log dosyası: {tester.log_file}", "INFO")
    
    # Testleri çalıştır
    tester.test_eicar()
    tester.test_suspicious_python_file()
    tester.test_rapid_file_creation()
    tester.test_suspicious_strings()
    tester.test_file_encryption_simulation()
    
    # Sonuçları göster
    tester.print_results()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Test kullanıcı tarafından iptal edildi.{Colors.END}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Hata oluştu: {str(e)}{Colors.END}\n")
        sys.exit(1)
