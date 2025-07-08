# QRadar Log İletimi Kurulum Projesi

![QRadar](https://img.shields.io/badge/IBM-QRadar-blue?style=flat-square)
![Linux](https://img.shields.io/badge/OS-Linux-yellow?style=flat-square)
![Bash](https://img.shields.io/badge/Shell-Bash-green?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.6+-red?style=flat-square)
![Türkçe](https://img.shields.io/badge/Dil-Türkçe-red?style=flat-square)

Linux sistemlerinden IBM QRadar SIEM'e audit log'larını güvenli ve verimli bir şekilde ileten enterprise seviyesinde, üretim ortamı hazır çözüm.

## 🚀 Özellikler

### ✨ Universal Destek
- **Tüm Linux Dağıtımları**: Ubuntu, Debian, RHEL, CentOS, Rocky, AlmaLinux, Oracle Linux, Amazon Linux, Kali Linux
- **Otomatik Tespit**: Sistem dağıtımını otomatik olarak tespit eder ve uygun installer'ı çalıştırır
- **Sürüm Uyumluluğu**: Her dağıtımın farklı sürümleri için optimize edilmiş yapılandırma

### 🛡️ Güvenlik ve Monitoring
- **MITRE ATT&CK Uyumlu**: 50+ MITRE ATT&CK tekniği için özel audit kuralları
- **Gelişmiş Filtreleme**: Sadece güvenlik ile ilgili olayları iletir
- **EXECVE İşleme**: Komut argümanlarını otomatik olarak birleştirir
- **Güvenli Kod**: `eval` kullanmaz, güvenli komut çalıştırma

### ⚙️ Teknik Özellikler
- **Fallback Mekanizmaları**: Audit kuralları yüklenemezse otomatik fallback
- **Enterprise Performans**: Yüksek hacimli ortamlar için optimize edilmiş
- **Comprehensive Logging**: Detaylı kurulum ve hata logları
- **Automatic Backup**: Mevcut yapılandırmaların otomatik yedeklenmesi

## 📋 Desteklenen Sistemler

### Ubuntu
- Ubuntu 16.04 LTS (Xenial Xerus)
- Ubuntu 18.04 LTS (Bionic Beaver)
- Ubuntu 20.04 LTS (Focal Fossa)
- Ubuntu 22.04 LTS (Jammy Jellyfish)
- Ubuntu 24.04 LTS (Noble Numbat)

### Debian
- Debian 9 (Stretch)
- Debian 10 (Buster)
- Debian 11 (Bullseye)
- Debian 12 (Bookworm)
- Kali Linux (tüm sürümler)

### RHEL Ailesi
- Red Hat Enterprise Linux 7, 8, 9
- CentOS 7, 8, Stream 8, Stream 9
- Rocky Linux 8, 9
- AlmaLinux 8, 9
- Oracle Linux 7, 8, 9
- Amazon Linux 2

## 🛠️ Kurulum

### Hızlı Başlangıç

```bash
# Repository'yi klonlayın
git clone https://github.com/00gxd14g/QRadar_Log_Forwarding.git
cd QRadar_Log_Forwarding

# Universal installer'ı çalıştırın (önerilen)
sudo bash src/installers/universal/qradar_universal_installer.sh 192.168.1.100 514
```

### Dağıtıma Özel Kurulum

#### Ubuntu için
```bash
sudo bash src/installers/ubuntu/qradar_ubuntu_installer.sh 192.168.1.100 514
```

#### Debian/Kali için
```bash
sudo bash src/installers/debian/qradar_debian_installer.sh 192.168.1.100 514
```

#### RHEL/CentOS/Rocky/AlmaLinux için
```bash
sudo bash src/installers/rhel/qradar_rhel_installer.sh 192.168.1.100 514
```

### Parametre Açıklamaları

| Parametre | Açıklama | Örnek |
|-----------|----------|-------|
| `QRADAR_IP` | QRadar sunucunuzun IP adresi | `192.168.1.100` |
| `QRADAR_PORT` | Log iletimi için port numarası | `514` |

## 🔧 Yapılandırma Detayları

### Oluşturulan Dosyalar

```
/etc/audit/rules.d/99-qradar.rules          # Audit kuralları
/etc/audit/plugins.d/syslog.conf             # Audit plugin yapılandırması
/etc/rsyslog.d/99-qradar.conf                # Rsyslog QRadar yapılandırması
/usr/local/bin/qradar_execve_parser.py       # EXECVE komut ayrıştırıcısı
/var/log/qradar_*_setup.log                  # Kurulum logları
/etc/qradar_backup_YYYYMMDD_HHMMSS/          # Yapılandırma yedekleri
```

### Audit Monitoring Kapsamı

#### Sistem Yönetimi
- Parola dosyası değişiklikleri (`/etc/passwd`, `/etc/shadow`)
- Kullanıcı ve grup yönetimi
- Sudo yapılandırma değişiklikleri
- SSH yapılandırma monitoring

#### Komut Çalıştırma
- Tüm root komutları (`euid=0`)
- Kullanıcı komutları (`euid>=1000`)
- Yetki yükseltme denemeleri (`su`, `sudo`)
- Shell ve interpreter kullanımı

#### Ağ Yapılandırması
- Hostname ve domain değişiklikleri
- Ağ interface yapılandırması
- Hosts dosyası değişiklikleri
- DNS yapılandırma değişiklikleri

#### Şüpheli Aktiviteler
- Ağ araçları kullanımı (`wget`, `curl`, `nc`)
- Uzaktan erişim araçları (`ssh`, `scp`, `rsync`)
- Sistem keşif komutları
- Pentest araçları (Kali Linux'ta)

## 🔍 Test ve Doğrulama

### Otomatik Testler

Script aşağıdaki testleri otomatik olarak yapar:

1. **Servis Durumu**: auditd ve rsyslog servislerinin çalışıp çalışmadığı
2. **Yapılandırma Geçerliliği**: rsyslog yapılandırma sözdizimi kontrolü
3. **Local Syslog Testi**: Test mesajının local syslog'a yazılması
4. **Audit Fonksiyonalitesi**: Audit olaylarının oluşup oluşmadığı
5. **QRadar Bağlantısı**: QRadar sunucusuna ağ bağlantısı

### Manuel Test Komutları

#### Local Syslog Testi
```bash
logger -p local3.info "QRadar test mesajı"
```

#### Audit Olayı Testi
```bash
sudo touch /etc/passwd  # identity_changes audit kuralını tetikler
```

#### Ağ Bağlantısı Testi
```bash
telnet 192.168.1.100 514
```

#### EXECVE Parser Testi
```bash
python3 /usr/local/bin/qradar_execve_parser.py --test
```

#### Ağ Trafiği Monitoring
```bash
sudo tcpdump -i any host 192.168.1.100 and port 514 -A -n
```

## 🛡️ Güvenlik Yapılandırmaları

### SELinux (RHEL Ailesi)

Script otomatik olarak şunları yapar:
- `rsyslog_can_network_connect` boolean'ını aktifleştirir
- Python script için uygun SELinux context ayarlar
- Audit log dosyaları için context düzeltmesi yapar

### Firewall (RHEL Ailesi)

Firewalld aktifse:
- QRadar portunu otomatik olarak açar
- Değişiklikleri kalıcı hale getirir
- Kural aktivasyonunu doğrular

### Dosya İzinleri

Tüm yapılandırma dosyaları uygun izinlerle oluşturulur:
- Audit kuralları: `640` (root:root)
- Plugin yapılandırmaları: `640` (root:root)
- Python script: `755` (çalıştırılabilir)
- Log dosyaları: `640` (root:root)

## 📊 Log Formatı ve İşleme

### Orijinal EXECVE Formatı
```
type=EXECVE msg=audit(1618834123.456:789): argc=3 a0="ls" a1="-la" a2="/tmp"
```

### İşlenmiş Format
```
UBUNTU_PROCESSED: type=EXECVE msg=audit(1618834123.456:789): cmd="ls -la /tmp" mitre_techniques="T1083" system_type="Ubuntu"
```

### Faydaları
- **Basitleştirilmiş Parsing**: Tek `cmd` alanı yerine çoklu `aX` alanları
- **Daha İyi Okunabilirlik**: Komutun tamı SIEM'de görünür
- **Gelişmiş Analytics**: QRadar kuralları ve aramaları için daha kolay
- **MITRE Etiketleme**: Otomatik ATT&CK teknik tanımlama

## 🆘 Sorun Giderme

Kapsamlı sorun giderme için [SORUN_GIDERME.md](SORUN_GIDERME.md) dosyasına bakın.

### Yaygın Sorunlar

#### Servisler Başlamıyor
```bash
# Servis durumunu kontrol et
sudo systemctl status auditd rsyslog

# Logları kontrol et
sudo journalctl -u auditd -f
sudo journalctl -u rsyslog -f
```

#### QRadar'a Log Gitmiyor
```bash
# Local syslog çalışıyor mu kontrol et
sudo grep "local3" /var/log/syslog

# Ağ bağlantısını kontrol et
sudo telnet <QRADAR_IP> <QRADAR_PORT>

# Giden trafiği izle
sudo tcpdump -i any host <QRADAR_IP> and port <QRADAR_PORT>
```

#### SELinux Engellemeleri
```bash
# AVC engellemelerini kontrol et
sudo ausearch -m avc -ts recent

# SELinux boolean'larını kontrol et
sudo getsebool -a | grep rsyslog
```

### Log Dosyaları

Sorun giderme için şu log dosyalarını kontrol edin:
- `/var/log/qradar_*_setup.log` - Kurulum script logları
- `/var/log/audit/audit.log` - Audit olayları
- `/var/log/syslog` veya `/var/log/messages` - Sistem logları

## 🔄 Bakım

### Düzenli Görevler

#### Audit Kurallarını Güncelleme
```bash
sudo nano /etc/audit/rules.d/99-qradar.rules
sudo augenrules --load
sudo systemctl restart auditd
```

#### Log Hacmini İzleme
```bash
# Audit log boyutunu kontrol et
sudo du -sh /var/log/audit/

# Syslog oranlarını izle
sudo journalctl -u rsyslog --since "1 hour ago" | wc -l
```

#### QRadar Bağlantısını Doğrulama
```bash
# Bağlantıyı periyodik olarak test et
timeout 5 bash -c "cat < /dev/null > /dev/tcp/<QRADAR_IP>/<QRADAR_PORT>"
```

### Yapılandırma Yedekleme

Script otomatik olarak yedek oluşturur:
```
/etc/qradar_backup_YYYYMMDD_HHMMSS/
```

Yedekten geri yüklemek için:
```bash
sudo cp /etc/qradar_backup_*/dosya_adı /etc/orijinal/konum/
sudo systemctl restart auditd rsyslog
```

## 🤝 Katkıda Bulunma

1. Repository'yi fork edin
2. Feature branch oluşturun (`git checkout -b feature/geliştirme`)
3. Değişikliklerinizi yapın
4. Yeni fonksiyonalite için testler ekleyin
5. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik eklendi'`)
6. Branch'inizi push edin (`git push origin feature/geliştirme`)
7. Pull Request oluşturun

## 📝 Lisans

Bu proje MIT Lisansı altında lisanslanmıştır - detaylar için [LICENSE](../../LICENSE) dosyasına bakın.

## 🆘 Destek ve Dokümantasyon

- **Sorunlar**: [GitHub Issues](https://github.com/00gxd14g/QRadar_Log_Forwarding/issues) üzerinde hata ve özellik isteklerini bildirin
- **Releases**: [GitHub Releases](https://github.com/00gxd14g/QRadar_Log_Forwarding/releases) üzerinden en son sürümleri indirin
- **Sorun Giderme**: Kapsamlı sorun giderme için [SORUN_GIDERME.md](SORUN_GIDERME.md) dosyasına bakın
- **Script Fonksiyonları**: [SCRIPT_FONKSIYONLARI.md](SCRIPT_FONKSIYONLARI.md) dosyasında tüm scriptlerin ne işe yaradığını öğrenin

## 📈 Son Güncellemeler

### Sürüm 4.0.0 (Mevcut) ✨

#### 🆕 Yeni Özellikler
- **Universal Installer**: Tüm Linux dağıtımları için tek script
- **Dağıtıma Özel Installer'lar**: Ubuntu, Debian, RHEL için optimize edilmiş ayrı scriptler
- **Gelişmiş MITRE ATT&CK Entegrasyonu**: Daha kapsamlı teknik mapping
- **Kali Linux Özel Desteği**: Penetration testing araçları için özel monitoring

#### 🔧 İyileştirmeler
- **Güvenlik**: `eval` kullanımının tamamen kaldırılması
- **Performans**: Enterprise ortamlar için optimize edilmiş kuyruk yönetimi
- **Hata Yönetimi**: Comprehensive error handling ve retry mekanizmaları
- **Dokümantasyon**: Tamamen Türkçe dokümantasyon ve kullanım kılavuzları

#### 🛠️ Teknik İyileştirmeler
- **Fallback Mekanizmaları**: Audit kuralları yüklenemediğinde otomatik fallback
- **SELinux/Firewall**: RHEL ailesi için otomatik güvenlik yapılandırması
- **Python Parser**: Her dağıtım için optimize edilmiş EXECVE parser
- **Logging**: Detaylı kurulum ve debug logları

---

**QRadar Universal Log Forwarding v4.0.0 ile güvenli monitoring altyapınızı oluşturun!** 🛡️

*Enterprise güvenlik gereksinimleri için tasarlanmış, production-ready çözüm*