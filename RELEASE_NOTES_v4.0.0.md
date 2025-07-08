# QRadar Log Forwarding v4.0.0 Release Notes

## 🚀 Major Release: Universal Installer Architecture

Bu sürüm, QRadar Log Forwarding projesinin en büyük güncellemesidir. Tamamen yeniden tasarlanan mimarisi ile tüm Linux dağıtımları için unified destek sağlar.

## ✨ Yeni Özellikler

### 🌐 Universal Installer System
- **Otomatik Dağıtım Tespiti**: Sistem otomatik olarak tespit edilir ve uygun installer çalıştırılır
- **Tek Script Çözümü**: `qradar_universal_installer.sh` ile tüm dağıtımlar desteklenir
- **Dağıtıma Özel Optimizasyonlar**: Her dağıtım için ayrı optimize edilmiş installer'lar

### 🛡️ Güvenlik İyileştirmeleri
- **Eval Kullanımının Kaldırılması**: Tüm scriptlerde `eval` kullanımı tamamen kaldırıldı
- **Güvenli Komut Çalıştırma**: `safe_execute()` fonksiyonu ile güvenli command execution
- **Input Validation**: Comprehensive parameter validation ve sanitization

### 🎯 MITRE ATT&CK Framework Entegrasyonu
- **Dağıtıma Özel Mapping**: Her dağıtım için özelleştirilmiş MITRE ATT&CK technique mapping
- **50+ Teknik Desteği**: Kapsamlı ATT&CK framework coverage
- **Otomatik Etiketleme**: EXECVE komutları otomatik olarak MITRE teknikleriyle etiketlenir

### 📁 Yeni Proje Yapısı
```
src/
├── installers/
│   ├── ubuntu/qradar_ubuntu_installer.sh      # Ubuntu özel (16.04+)
│   ├── debian/qradar_debian_installer.sh      # Debian/Kali özel (9+)
│   ├── rhel/qradar_rhel_installer.sh          # RHEL ailesi (7+)
│   └── universal/qradar_universal_installer.sh # Universal installer
└── helpers/
    └── execve_parser.py                        # Gelişmiş EXECVE parser
```

## 🔧 Dağıtıma Özel İyileştirmeler

### Ubuntu Installer
- **Sürüm Uyumluluğu**: Ubuntu 16.04-24.04 tüm sürümler
- **Audisp Method Detection**: Sürüme göre legacy/modern audisp seçimi
- **Netplan Desteği**: Ubuntu network yapılandırması monitoring

### Debian/Kali Installer  
- **Kali Linux Özel Desteği**: Penetration testing araçları için özel monitoring
- **Pentest Tool Monitoring**: Nmap, Metasploit, John, Hashcat vb. araçlar
- **APT Optimizasyonu**: Debian paket sistemi optimizasyonu

### RHEL Ailesi Installer
- **SELinux Otomatik Yapılandırması**: Automatic SELinux boolean ve context ayarları
- **Firewalld Entegrasyonu**: QRadar portu için otomatik firewall kuralları  
- **YUM/DNF Desteği**: Intelligent package manager detection
- **Enterprise Features**: Enterprise ortamlar için optimize edilmiş ayarlar

## 📚 Türkçe Dokümantasyon

### Yeni Dokümantasyon Dosyaları
- **`docs/tr/README.md`**: Kapsamlı Türkçe kullanım kılavuzu
- **`docs/tr/SCRIPT_FONKSIYONLARI.md`**: Tüm script fonksiyonlarının detaylı açıklaması
- **`docs/tr/SORUN_GIDERME.md`**: Comprehensive troubleshooting guide

### Dokümantasyon Özellikleri
- **Detaylı Kurulum Rehberi**: Adım adım kurulum talimatları
- **Sorun Giderme**: Yaygın sorunlar ve çözümleri
- **Test Komutları**: Comprehensive testing ve validation
- **Performance Tuning**: Optimizasyon rehberleri

## 🚨 Breaking Changes

### Dosya Lokasyon Değişiklikleri
- **Eski**: Çeşitli dizinlerde dağınık scriptler
- **Yeni**: `src/installers/` altında organize edilmiş yapı

### Script İsimleri
- **Eski**: `setup-ubuntu2004.sh`, `qradar_unified_setup.sh`
- **Yeni**: Dağıtıma özel isimler (`qradar_ubuntu_installer.sh`)

### Yapılandırma Dosyaları
- **Yeni**: `99-qradar.rules`, `99-qradar.conf` (priority optimized)
- **Python Parser**: `qradar_execve_parser.py` (enhanced functionality)

## 🔄 Upgrade Path

### Mevcut Kurulumlardan Upgrade
```bash
# Mevcut yapılandırmayı yedekle
sudo tar -czf qradar-backup-$(date +%Y%m%d).tar.gz /etc/audit/ /etc/rsyslog.d/

# Yeni sürümü indir
git pull origin main

# Universal installer çalıştır
sudo bash src/installers/universal/qradar_universal_installer.sh <QRADAR_IP> <PORT>
```

## 🧪 Test Coverage

### Otomatik Testler
- **Service Status Validation**: auditd, rsyslog status checks
- **Configuration Syntax**: rsyslog, audit rules validation  
- **Network Connectivity**: QRadar reachability tests
- **EXECVE Parser**: Functionality validation
- **End-to-End**: Complete log flow testing

### Platform Testing
- ✅ Ubuntu 20.04, 22.04, 24.04
- ✅ Debian 11, 12
- ✅ Kali Linux 2024
- ✅ RHEL 8, 9
- ✅ CentOS Stream 8, 9
- ✅ Rocky Linux 8, 9
- ✅ AlmaLinux 8, 9

## 📊 Performance Improvements

### Optimizasyon Alanları
- **Queue Management**: Advanced rsyslog queueing (linkedlist, disk buffering)
- **Rate Limiting**: Intelligent audit rate limiting (150 events/sec)
- **Memory Usage**: Optimized buffer sizes (16384 audit buffer)
- **Network Efficiency**: TCP framing with retry mechanisms

### Scalability
- **Enterprise Ready**: Tested in high-volume environments
- **Fallback Mechanisms**: Multiple audit loading methods
- **Error Recovery**: Comprehensive retry and recovery systems

## 🐛 Bug Fixes

### Security Fixes
- **CVE-Prevention**: Removal of eval usage eliminates code injection risks
- **Input Sanitization**: All user inputs properly validated
- **File Permissions**: Proper security context for all created files

### Stability Fixes  
- **Service Dependencies**: Improved service startup sequencing
- **Configuration Validation**: Syntax checking before service restart
- **Network Resilience**: Better handling of network interruptions

## 🔮 Gelecek Sürümler için Roadmap

### v4.1.0 (Planlanan)
- **SIEM Integration**: Multiple SIEM support (Splunk, Elastic)
- **Advanced Analytics**: Machine learning based threat detection
- **Dashboard**: Web-based monitoring dashboard

### v4.2.0 (Planlanan)
- **Container Support**: Docker/Kubernetes deployment
- **Cloud Integration**: AWS, Azure, GCP native support
- **API Integration**: RESTful API for management

## 📞 Destek ve İletişim

### Dokümantasyon
- **Ana README**: [docs/tr/README.md](docs/tr/README.md)
- **Script Fonksiyonları**: [docs/tr/SCRIPT_FONKSIYONLARI.md](docs/tr/SCRIPT_FONKSIYONLARI.md)
- **Sorun Giderme**: [docs/tr/SORUN_GIDERME.md](docs/tr/SORUN_GIDERME.md)

### Community Support
- **GitHub Issues**: Bug reports ve feature requests
- **GitHub Discussions**: Community Q&A
- **Wiki**: Community maintained documentation

## 🎉 Katkıda Bulunanlar

Bu release'e katkıda bulunan herkese teşekkürler:
- **Claude AI**: Complete architecture redesign ve documentation
- **Community**: Testing ve feedback

---

## Installation Commands

### Universal Installer (Önerilen)
```bash
git clone https://github.com/00gxd14g/QRadar_Log_Forwarding.git
cd QRadar_Log_Forwarding
sudo bash src/installers/universal/qradar_universal_installer.sh 192.168.1.100 514
```

### Dağıtıma Özel Installer'lar
```bash
# Ubuntu için
sudo bash src/installers/ubuntu/qradar_ubuntu_installer.sh 192.168.1.100 514

# Debian/Kali için  
sudo bash src/installers/debian/qradar_debian_installer.sh 192.168.1.100 514

# RHEL ailesi için
sudo bash src/installers/rhel/qradar_rhel_installer.sh 192.168.1.100 514
```

---

**QRadar Log Forwarding v4.0.0 - Enterprise Güvenlik İzleme Çözümü** 🛡️

*Tüm Linux dağıtımları için production-ready, güvenli ve ölçeklenebilir çözüm*