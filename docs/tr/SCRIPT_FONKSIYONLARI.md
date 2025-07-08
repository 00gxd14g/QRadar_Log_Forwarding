# QRadar Script Fonksiyonları ve Açıklamaları

Bu dokümanda QRadar Log Forwarding projesindeki tüm scriptlerin ne işe yaradığı, nasıl çalıştığı ve hangi durumlarda kullanılacağı detaylı olarak açıklanmaktadır.

## 📁 Proje Yapısı ve Script Lokasyonları

```
QRadar_Log_Forwarding/
├── src/
│   ├── installers/
│   │   ├── ubuntu/qradar_ubuntu_installer.sh     # Ubuntu özel installer
│   │   ├── debian/qradar_debian_installer.sh     # Debian/Kali özel installer
│   │   ├── rhel/qradar_rhel_installer.sh         # RHEL ailesi özel installer
│   │   └── universal/qradar_universal_installer.sh # Universal installer
│   └── helpers/
│       └── execve_parser.py                       # EXECVE log ayrıştırıcısı
```

## 🔧 Ana Installer Scriptleri

### 1. Universal Installer (`qradar_universal_installer.sh`)

#### **Ne İşe Yarar**
Tüm Linux dağıtımlarında çalışan master installer script'i. Sistemi otomatik olarak tespit eder ve uygun dağıtıma özel installer'ı çalıştırır.

#### **Ana Fonksiyonları**
- **Sistem Tespiti**: `/etc/os-release` dosyasından dağıtım bilgisini okur
- **Installer Seçimi**: Tespit edilen dağıtıma göre uygun installer'ı seçer
- **Otomatik Yönlendirme**: Seçilen installer'ı otomatik olarak çalıştırır

#### **Desteklenen Dağıtımlar**
```bash
Ubuntu    -> ubuntu/qradar_ubuntu_installer.sh
Debian    -> debian/qradar_debian_installer.sh
Kali      -> debian/qradar_debian_installer.sh
RHEL      -> rhel/qradar_rhel_installer.sh
CentOS    -> rhel/qradar_rhel_installer.sh
Rocky     -> rhel/qradar_rhel_installer.sh
AlmaLinux -> rhel/qradar_rhel_installer.sh
Oracle    -> rhel/qradar_rhel_installer.sh
Amazon    -> rhel/qradar_rhel_installer.sh
```

#### **Kullanım**
```bash
sudo bash src/installers/universal/qradar_universal_installer.sh 192.168.1.100 514
```

#### **Çalışma Prensibi**
1. `/etc/os-release` dosyasını okur
2. `ID` alanından dağıtımı tespit eder
3. Uygun installer path'ini belirler
4. Hedef installer'ın varlığını kontrol eder
5. Installer'ı çalıştırır ve sonucu raporlar

---

### 2. Ubuntu Installer (`qradar_ubuntu_installer.sh`)

#### **Ne İşe Yarar**
Ubuntu'nun tüm sürümleri (16.04+) için optimize edilmiş özel installer. Ubuntu'ya özgü paket yapısı ve sistem özelliklerini dikkate alır.

#### **Ubuntu Özel Özellikleri**
- **Sürüm Uyumluluğu**: Ubuntu 16.04-24.04 arası tüm sürümleri destekler
- **Audisp Metod Tespiti**: Ubuntu sürümüne göre legacy/modern audisp seçimi
- **APT Optimizasyonu**: Ubuntu paket yöneticisi için optimize edilmiş kurulum

#### **Ana Fonksiyonları**

##### `detect_ubuntu_version()`
```bash
# Ubuntu sürüm tespiti ve doğrulama
- /etc/os-release okuma
- VERSION_ID parsing (20.04, 22.04 gibi)
- Ubuntu 16.04+ kontrolü
- Audisp metod belirleme
```

##### `determine_audisp_method()`
```bash
# Ubuntu sürümüne göre audisp metodu
Ubuntu 16.04-19.10: /etc/audisp/plugins.d/ (legacy)
Ubuntu 20.04+:      /etc/audit/plugins.d/  (modern)
```

##### `configure_auditd()`
```bash
# Ubuntu için özel audit kuralları
- Netplan yapılandırma monitoring
- Ubuntu özel sistem dizinleri
- Unity/GNOME masaüstü monitoring
```

#### **Kullanım**
```bash
sudo bash src/installers/ubuntu/qradar_ubuntu_installer.sh 192.168.1.100 514
```

#### **Ubuntu Özel Audit Kuralları**
- `/etc/netplan/` - Ubuntu network yapılandırması
- `/etc/network/interfaces` - Legacy network yapılandırması
- Ubuntu özel sistem servisleri

---

### 3. Debian/Kali Installer (`qradar_debian_installer.sh`)

#### **Ne İşe Yarar**
Debian ve Kali Linux için optimize edilmiş installer. Kali'nin penetration testing araçları için özel monitoring kuralları içerir.

#### **Debian/Kali Özel Özellikleri**
- **Kali Tespiti**: Kali Linux özel tespit ve yapılandırma
- **Pentest Araçları**: Kali'deki pentest araçları için özel monitoring
- **APT Optimizasyonu**: Debian paket sistemi optimizasyonu

#### **Ana Fonksiyonları**

##### `detect_debian_version()`
```bash
# Debian/Kali tespit ve sürüm belirleme
- ID alanından debian/kali tespiti
- IS_KALI flag ayarlama
- Debian 9+ sürüm kontrolü
- Audisp metod belirleme
```

##### **Kali Linux Özel Monitoring**
```bash
# Penetration Testing Araçları
-w /usr/bin/nmap -p x -k pentest_tools
-w /usr/bin/msfconsole -p x -k pentest_tools
-w /usr/bin/john -p x -k pentest_tools
-w /usr/bin/hashcat -p x -k pentest_tools
-w /usr/bin/hydra -p x -k pentest_tools
-w /usr/bin/nikto -p x -k pentest_tools
-w /usr/bin/sqlmap -p x -k pentest_tools
-w /usr/bin/aircrack-ng -p x -k pentest_tools
```

##### **EXECVE Parser Kali Özel MITRE Mapping**
```python
# Kali özel MITRE teknikleri
'T1018': ['nmap', 'netdiscover', 'arp-scan', 'fping']
'T1046': ['nmap', 'masscan', 'zmap', 'rustscan']
'T1003': ['john', 'hashcat'] # Password cracking
```

#### **Kullanım**
```bash
sudo bash src/installers/debian/qradar_debian_installer.sh 192.168.1.100 514
```

---

### 4. RHEL Ailesi Installer (`qradar_rhel_installer.sh`)

#### **Ne İşe Yarar**
RHEL, CentOS, Rocky, AlmaLinux, Oracle Linux ve Amazon Linux için optimize edilmiş installer. SELinux ve Firewalld otomatik yapılandırması içerir.

#### **RHEL Özel Özellikleri**
- **Paket Yöneticisi Tespiti**: YUM/DNF otomatik tespiti
- **SELinux Yapılandırması**: Otomatik SELinux boolean ve context ayarları
- **Firewalld Yönetimi**: QRadar portu için otomatik firewall kuralları
- **Enterprise Optimizasyon**: Enterprise ortamlar için optimize edilmiş ayarlar

#### **Ana Fonksiyonları**

##### `detect_rhel_family()`
```bash
# RHEL ailesi dağıtım tespiti
Supported: rhel, centos, rocky, almalinux, ol, amzn
VERSION_MAJOR extraction (7, 8, 9)
Package manager determination (yum/dnf)
```

##### `determine_package_manager()`
```bash
# Paket yöneticisi belirleme
RHEL 8+, Rocky, AlmaLinux: DNF (available) | YUM (fallback)
RHEL 7, CentOS 7:          YUM
Amazon Linux 2:            YUM
```

##### `check_system_features()`
```bash
# Sistem özellikleri tespiti
- SELinux status (getenforce)
- Firewalld status (systemctl)
- Syslog file location (/var/log/messages)
```

##### `configure_selinux()`
```bash
# SELinux otomatik yapılandırması
setsebool -P rsyslog_can_network_connect on
restorecon -R /usr/local/bin/qradar_execve_parser.py
restorecon -R /var/log/audit/
```

##### `configure_firewall()`
```bash
# Firewalld otomatik yapılandırması
firewall-cmd --permanent --add-port=514/tcp
firewall-cmd --reload
```

#### **RHEL Özel Audit Kuralları**
```bash
# RHEL network configuration
-w /etc/sysconfig/network -p wa -k network_config
-w /etc/sysconfig/network-scripts/ -p wa -k network_config

# SELinux monitoring
-w /etc/selinux/config -p wa -k selinux_config
-w /usr/sbin/setenforce -p x -k selinux_enforcement

# Package management
-w /usr/bin/yum -p x -k package_management
-w /usr/bin/dnf -p x -k package_management
```

#### **Kullanım**
```bash
sudo bash src/installers/rhel/qradar_rhel_installer.sh 192.168.1.100 514
```

---

## 🐍 Python Helper Script

### EXECVE Parser (`execve_parser.py`)

#### **Ne İşe Yarar**
Audit EXECVE mesajlarını işleyerek komut argümanlarını tek bir alana birleştirir ve MITRE ATT&CK tekniklerine göre etiketler.

#### **Ana Fonksiyonları**

##### **Komut Argüman Birleştirme**
```python
# Orijinal format
type=EXECVE msg=audit(123:456): argc=3 a0="ls" a1="-la" a2="/tmp"

# İşlenmiş format  
PROCESSED: type=EXECVE msg=audit(123:456): cmd="ls -la /tmp"
```

##### **MITRE ATT&CK Mapping**
```python
MITRE_TECHNIQUES = {
    'T1003': ['cat /etc/shadow', 'getent shadow'],  # Credential Access
    'T1059': ['bash', 'python', 'perl'],            # Command Execution
    'T1070': ['history -c', 'shred'],               # Defense Evasion
    'T1105': ['scp', 'rsync', 'wget'],              # Ingress Tool Transfer
    'T1548': ['sudo', 'su -', 'pkexec'],           # Privilege Escalation
}
```

##### **Dağıtıma Özel Özellikler**
```python
# Ubuntu Parser
system_type="Ubuntu"
prefix="UBUNTU_PROCESSED:"

# Debian/Kali Parser  
system_type="Debian" | "Kali"
prefix="DEBIAN_PROCESSED:"
kali_tools=['nmap', 'msfconsole', 'john']

# RHEL Parser
system_type="RHEL" | "CentOS" | "Rocky" | "AlmaLinux"
prefix="RHEL_PROCESSED:"
enterprise_tools=['systemctl', 'firewall-cmd']
```

#### **Test Modu**
```bash
python3 /usr/local/bin/qradar_execve_parser.py --test
```

---

## 🔄 Ortak Fonksiyonlar (Tüm Installer'larda)

### 1. **Logging Sistemi**
```bash
log() {
    local level="${1:-INFO}"
    local message="$2"
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}
```

### 2. **Güvenli Komut Çalıştırma**
```bash
safe_execute() {
    local description="$1"
    shift
    # eval kullanmaz - güvenli command execution
    if "$@" >> "$LOG_FILE" 2>&1; then
        return 0
    else
        return $exit_code
    fi
}
```

### 3. **Retry Mekanizması**
```bash
retry_operation() {
    local max_attempts=3
    for ((attempt=1; attempt<=max_attempts; attempt++)); do
        if safe_execute "$description" "$@"; then
            return 0
        fi
        sleep 5
    done
}
```

### 4. **Dosya Yedekleme**
```bash
backup_file() {
    local file="$1"
    local backup_file="$BACKUP_DIR/$(basename "$file").$(date +%H%M%S)"
    cp "$file" "$backup_file"
}
```

### 5. **Audit Kuralları Yükleme (Multi-Method)**
```bash
load_audit_rules() {
    # Method 1: augenrules (modern)
    augenrules --load
    
    # Method 2: auditctl direct
    auditctl -R "$AUDIT_RULES_FILE"
    
    # Method 3: Line by line (fallback)
    while read -r line; do
        auditctl "$line"
    done < "$AUDIT_RULES_FILE"
}
```

### 6. **Comprehensive Validation**
```bash
run_validation_tests() {
    # Service status check
    # Rsyslog syntax validation  
    # EXECVE parser test
    # Local syslog test
    # QRadar connectivity test
    # Audit functionality test
}
```

---

## 📊 Yapılandırma Dosyaları

### 1. **Audit Rules (`99-qradar.rules`)**
```bash
# Her dağıtım için optimize edilmiş audit kuralları
# MITRE ATT&CK framework uyumlu
# Güvenlik odaklı filtreleme
# Performance optimized (buffer: 16384, rate: 150)
```

### 2. **Rsyslog Configuration (`99-qradar.conf`)**
```bash
# Modern rsyslog yapılandırması
# Queue management (linkedlist, disk buffering)
# TCP reliable delivery
# EXECVE processing through omprog
# Noise reduction filters
```

### 3. **Audisp/Audit Plugin (`syslog.conf`)**
```bash
# Dağıtım uyumlu plugin yapılandırması
# LOG_LOCAL3 facility
# builtin_syslog method
```

---

## 🔍 Debug ve Troubleshooting

### Log Dosyaları
```bash
/var/log/qradar_universal_setup.log     # Universal installer
/var/log/qradar_ubuntu_setup.log        # Ubuntu installer  
/var/log/qradar_debian_setup.log        # Debian installer
/var/log/qradar_rhel_setup.log          # RHEL installer
```

### Test Komutları
```bash
# Parser test
python3 /usr/local/bin/qradar_execve_parser.py --test

# Service status
systemctl status auditd rsyslog

# Configuration validation
rsyslogd -N1

# Manual log test
logger -p local3.info "Test message"

# Audit test  
sudo touch /etc/passwd

# Network test
telnet <QRADAR_IP> <QRADAR_PORT>
```

---

## 🎯 Hangi Script'i Ne Zaman Kullanmalı

### **Universal Installer** 
✅ **Kullan**:
- Sistem türünü bilmiyorsanız
- Tek bir script ile tüm dağıtımları desteklemek istiyorsanız
- Otomatik deployment pipeline'larında
- En kolay ve güvenli seçenek

### **Ubuntu Installer**
✅ **Kullan**:
- Sadece Ubuntu sistemlerde çalışacaksanız
- Ubuntu özel optimizasyonları istiyorsanız
- Ubuntu network (netplan) yapılandırması önemliyse

### **Debian/Kali Installer** 
✅ **Kullan**:
- Debian/Kali sistemlerde çalışacaksanız
- Kali Linux pentest araçları monitoring önemliyse
- Debian özel paket yapılandırması gerekiyorsa

### **RHEL Installer**
✅ **Kullan**:
- Enterprise RHEL ortamlarında
- SELinux/Firewalld otomatik yapılandırması gerekiyorsa
- YUM/DNF optimizasyonu önemliyse
- RHEL özel sistem monitoring gerekiyorsa

---

**Sonuç**: Genel kullanım için **Universal Installer**'ı tercih edin. Özel optimizasyonlar gerekiyorsa dağıtıma özel installer'ları kullanın.