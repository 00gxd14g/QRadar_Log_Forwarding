# QRadar Log İletimi Sorun Giderme Kılavuzu

Bu kılavuz QRadar Log Forwarding kurulumu sırasında veya sonrasında karşılaşabileceğiniz tüm sorunlar ve çözümleri içerir.

## 🔍 Hızlı Tanı Kontrolleri

### Temel Sistem Kontrolü
```bash
# 1. Servis durumları
sudo systemctl status auditd
sudo systemctl status rsyslog

# 2. Yapılandırma dosyaları
ls -la /etc/audit/rules.d/99-qradar.rules
ls -la /etc/rsyslog.d/99-qradar.conf
ls -la /usr/local/bin/qradar_execve_parser.py

# 3. Log dosyaları
ls -la /var/log/qradar_*_setup.log
tail -50 /var/log/qradar_*_setup.log
```

### Hızlı Test Komutları
```bash
# Rsyslog yapılandırma testi
sudo rsyslogd -N1

# Python parser testi  
python3 /usr/local/bin/qradar_execve_parser.py --test

# QRadar bağlantı testi
timeout 5 bash -c "cat < /dev/null > /dev/tcp/QRADAR_IP/QRADAR_PORT"

# Local syslog testi
logger -p local3.info "QRadar test mesajı"
```

---

## 🚨 Kurulum Sırasında Karşılaşılan Sorunlar

### 1. **Script Çalıştırılamıyor**

#### **Sorun**: `Permission denied` hatası
```bash
bash: ./qradar_universal_installer.sh: Permission denied
```

#### **Çözüm**:
```bash
# Script'i çalıştırılabilir yapın
chmod +x src/installers/universal/qradar_universal_installer.sh

# Root yetkisiyle çalıştırın
sudo bash src/installers/universal/qradar_universal_installer.sh 192.168.1.100 514
```

---

### 2. **Dağıtım Tespiti Başarısız**

#### **Sorun**: `Desteklenmeyen dağıtım` hatası
```
ERROR: Bu script sadece Ubuntu sistemler için tasarlanmıştır. Tespit edilen: unknown
```

#### **Çözüm**:
```bash
# 1. OS-release dosyasını kontrol edin
cat /etc/os-release

# 2. Dağıtım ID'sini manuel kontrol edin
source /etc/os-release
echo "ID: $ID"
echo "VERSION_ID: $VERSION_ID"

# 3. Uygun installer'ı manuel seçin
# Ubuntu için:
sudo bash src/installers/ubuntu/qradar_ubuntu_installer.sh IP PORT

# Debian/Kali için:
sudo bash src/installers/debian/qradar_debian_installer.sh IP PORT

# RHEL ailesi için:
sudo bash src/installers/rhel/qradar_rhel_installer.sh IP PORT
```

---

### 3. **Paket Kurulum Sorunları**

#### **Sorun**: Paket kurulumu başarısız
```
ERROR: Package installation failed
```

#### **Ubuntu/Debian Çözümü**:
```bash
# 1. APT cache'i güncelle
sudo apt-get update

# 2. Paket listesini manuel kontrol et
sudo apt-get install -y auditd rsyslog python3

# 3. EPEL gerekiyorsa (eski Ubuntu)
sudo apt-get install -y software-properties-common
```

#### **RHEL/CentOS Çözümü**:
```bash
# 1. YUM/DNF cache'i temizle
sudo yum clean all    # veya dnf clean all

# 2. EPEL repository'si ekle (RHEL 7)
sudo yum install -y epel-release

# 3. Paketleri manuel kur
sudo yum install -y audit rsyslog python3    # veya dnf install
```

---

### 4. **Python Script Deploy Hatası**

#### **Sorun**: EXECVE parser kurulamıyor
```
ERROR: EXECVE parser script'i çalıştırılabilir yapılamadı
```

#### **Çözüm**:
```bash
# 1. Python3 kurulu mu kontrol et
python3 --version

# 2. Target directory mevcut mu kontrol et
sudo mkdir -p /usr/local/bin

# 3. Manuel deploy
sudo cp src/helpers/execve_parser.py /usr/local/bin/qradar_execve_parser.py
sudo chmod +x /usr/local/bin/qradar_execve_parser.py
sudo chown root:root /usr/local/bin/qradar_execve_parser.py

# 4. Test et
python3 /usr/local/bin/qradar_execve_parser.py --test
```

---

## ⚙️ Servis Sorunları

### 1. **Auditd Servisi Başlamıyor**

#### **Sorunlar ve Çözümler**:

##### **Sorun**: `auditd.service failed to start`
```bash
# 1. Servis durumunu detaylı kontrol et
sudo systemctl status auditd -l
sudo journalctl -u auditd --no-pager

# 2. Audit rules syntax'ını kontrol et
sudo auditctl -R /etc/audit/rules.d/99-qradar.rules

# 3. Problematic kuralları temizle
sudo auditctl -D

# 4. Kuralları satır satır yükle
while IFS= read -r line; do
    if [[ "$line" =~ ^-[a-zA-Z] ]]; then
        echo "Loading: $line"
        sudo auditctl $line || echo "Failed: $line"
    fi
done < /etc/audit/rules.d/99-qradar.rules
```

##### **Sorun**: `audit rules validation failed`
```bash
# Basitleştirilmiş kurallar ile başla
sudo cp /etc/audit/rules.d/99-qradar.rules /etc/audit/rules.d/99-qradar.rules.backup

# Minimal rules
sudo tee /etc/audit/rules.d/99-qradar.rules << 'EOF'
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
EOF

sudo systemctl restart auditd
```

---

### 2. **Rsyslog Servisi Sorunları**

#### **Sorun**: `rsyslog configuration error`
```bash
# 1. Syntax validation
sudo rsyslogd -N1

# 2. Configuration dosyasını kontrol et
sudo cat /etc/rsyslog.d/99-qradar.conf

# 3. Problematic config backup al ve temizle
sudo mv /etc/rsyslog.d/99-qradar.conf /etc/rsyslog.d/99-qradar.conf.backup

# 4. Minimal config ile başla
sudo tee /etc/rsyslog.d/99-qradar.conf << EOF
# Minimal QRadar config
if \$syslogfacility-text == "local3" then {
    action(
        type="omfwd"
        target="QRADAR_IP"
        port="QRADAR_PORT" 
        protocol="tcp"
    )
    stop
}
EOF

sudo systemctl restart rsyslog
```

#### **Sorun**: `omprog module not found`
```bash
# 1. Rsyslog version kontrol
rsyslogd -version

# 2. Omprog modülü mevcut mu kontrol et
find /usr /lib -name "*omprog*" 2>/dev/null

# 3. Rsyslog-full paketi kur (Ubuntu/Debian)
sudo apt-get install rsyslog rsyslog-pgsql rsyslog-mysql

# 4. RHEL için additional modules
sudo yum install rsyslog-module-* # veya dnf install
```

---

## 🌐 Ağ Bağlantı Sorunları

### 1. **QRadar'a Bağlantı Kurulamıyor**

#### **Temel Testler**:
```bash
# 1. Ping testi
ping -c 4 QRADAR_IP

# 2. Port erişilebilirlik
telnet QRADAR_IP QRADAR_PORT
# veya
nc -zv QRADAR_IP QRADAR_PORT

# 3. TCP connection test
timeout 5 bash -c "cat < /dev/null > /dev/tcp/QRADAR_IP/QRADAR_PORT"
echo $?  # 0 = başarılı, 1 = başarısız
```

#### **Sorun**: Connection refused
```bash
# 1. QRadar sunucusu çalışıyor mu kontrol et
# 2. Port doğru mu kontrol et (514, 1514, 5140 yaygın)
# 3. Protocol doğru mu kontrol et (TCP/UDP)

# 4. Alternative port test
for port in 514 1514 5140 6514; do
    echo "Testing port $port..."
    timeout 3 bash -c "cat < /dev/null > /dev/tcp/QRADAR_IP/$port" && echo "Port $port: OPEN" || echo "Port $port: CLOSED"
done
```

#### **Sorun**: Firewall blokajı
```bash
# 1. Local firewall kontrol (RHEL/CentOS)
sudo firewall-cmd --list-all
sudo firewall-cmd --permanent --add-port=QRADAR_PORT/tcp
sudo firewall-cmd --reload

# 2. Iptables kontrol (diğer dağıtımlar)
sudo iptables -L -n
sudo iptables -A OUTPUT -p tcp --dport QRADAR_PORT -j ACCEPT

# 3. UFW kontrol (Ubuntu)
sudo ufw status
sudo ufw allow out QRADAR_PORT/tcp
```

---

## 🔒 SELinux Sorunları (RHEL Ailesi)

### 1. **SELinux Denial'ları**

#### **Sorun**: `rsyslog network connection denied`
```bash
# 1. AVC denial'ları kontrol et
sudo ausearch -m avc -ts recent

# 2. Rsyslog network boolean kontrol et
sudo getsebool rsyslog_can_network_connect

# 3. Boolean'ı aktifleştir
sudo setsebool -P rsyslog_can_network_connect on

# 4. Doğrula
sudo getsebool rsyslog_can_network_connect
```

#### **Sorun**: `Python script execution denied`
```bash
# 1. Script context'i kontrol et
ls -Z /usr/local/bin/qradar_execve_parser.py

# 2. Context'i düzelt
sudo restorecon -v /usr/local/bin/qradar_execve_parser.py

# 3. Executable context ver
sudo semanage fcontext -a -t bin_t /usr/local/bin/qradar_execve_parser.py
sudo restorecon -v /usr/local/bin/qradar_execve_parser.py
```

#### **Sorun**: `audit log access denied`
```bash
# 1. Audit log context'leri kontrol et
ls -Z /var/log/audit/

# 2. Context'leri düzelt
sudo restorecon -R /var/log/audit/

# 3. Rsyslog audit access boolean
sudo setsebool -P rsyslog_read_audit_logs on
```

---

## 📊 Log İletimi Sorunları

### 1. **Loglar QRadar'a Gitmiyor**

#### **Troubleshooting Adımları**:

##### **Adım 1: Local syslog çalışıyor mu?**
```bash
# Test mesajı gönder
logger -p local3.info "QRadar test mesajı $(date)"

# Local syslog'da görünüyor mu kontrol et
# Ubuntu/Debian:
sudo grep "QRadar test" /var/log/syslog

# RHEL/CentOS:
sudo grep "QRadar test" /var/log/messages
```

##### **Adım 2: Rsyslog QRadar config aktif mi?**
```bash
# Config dosyası mevcut mu
cat /etc/rsyslog.d/99-qradar.conf

# Config yüklenmiş mi kontrol et
sudo rsyslogd -N1 | grep -i qradar
```

##### **Adım 3: Network trafiği var mı?**
```bash
# Outgoing traffic monitoring
sudo tcpdump -i any host QRADAR_IP and port QRADAR_PORT -A -n

# Test mesajı gönderirken trace al
logger -p local3.info "QRadar network test $(date)"
```

##### **Adım 4: Python parser çalışıyor mu?**
```bash
# Parser test
python3 /usr/local/bin/qradar_execve_parser.py --test

# Parser log çıktıları
sudo grep -i execve /var/log/messages
```

---

### 2. **Audit Events QRadar'a Gitmiyor**

#### **Sorun**: Audit events oluşmuyor
```bash
# 1. Audit rules yüklü mü kontrol et
sudo auditctl -l | head -20

# 2. Test audit event oluştur
sudo touch /etc/passwd
sudo cat /etc/passwd > /dev/null

# 3. Audit log'da görünüyor mu
sudo ausearch --start today -k identity_changes
sudo tail -20 /var/log/audit/audit.log | grep SYSCALL
```

#### **Sorun**: Audit events syslog'a gitmiyor
```bash
# 1. Audisp plugin aktif mi kontrol et
# Ubuntu 20.04+:
sudo cat /etc/audit/plugins.d/syslog.conf

# Ubuntu 16.04-19.10:
sudo cat /etc/audisp/plugins.d/syslog.conf

# 2. Plugin config doğru mu
grep -E "active.*yes|LOG_LOCAL3" /etc/audit*/plugins.d/syslog.conf

# 3. Auditd restart
sudo systemctl restart auditd
```

---

## 🔧 Performance ve Optimizasyon Sorunları

### 1. **Yüksek Log Volume**

#### **Sorun**: Çok fazla log üretiliyor
```bash
# 1. Log volume analizi
sudo du -sh /var/log/audit/
sudo wc -l /var/log/audit/audit.log

# 2. En çok log üreten kuralları bul
sudo ausearch --start today | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

# 3. Rate limiting artır
sudo sed -i 's/-r 150/-r 50/' /etc/audit/rules.d/99-qradar.rules
sudo augenrules --load
```

#### **Çözüm**: Filtreleme artırın
```bash
# Gürültülü kuralları disable et
sudo auditctl -D

# Sadece kritik kuralları yükle
sudo tee /etc/audit/rules.d/99-qradar-minimal.rules << 'EOF'
-D
-b 8192
-f 1
-r 50

# Sadece kritik olaylar
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/sudoers -p wa -k privilege_changes
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands

# Rate limit
-r 50
EOF

sudo systemctl restart auditd
```

---

### 2. **Memory/CPU Kullanımı Yüksek**

#### **Rsyslog Memory Optimization**:
```bash
# Rsyslog queue boyutunu düşür
sudo sed -i 's/queue.size="100000"/queue.size="10000"/' /etc/rsyslog.d/99-qradar.conf
sudo sed -i 's/queue.dequeuebatchsize="1000"/queue.dequeuebatchsize="100"/' /etc/rsyslog.d/99-qradar.conf

sudo systemctl restart rsyslog
```

#### **Audit Buffer Optimization**:
```bash
# Buffer size düşür
sudo sed -i 's/-b 16384/-b 8192/' /etc/audit/rules.d/99-qradar.rules
sudo augenrules --load
```

---

## 🧪 Test ve Doğrulama

### 1. **End-to-End Test**

#### **Complete Test Sequence**:
```bash
#!/bin/bash
# QRadar End-to-End Test Script

echo "=== QRadar Log Forwarding Test ==="

# 1. Service status
echo "1. Service Status:"
systemctl is-active auditd && echo "✓ auditd: RUNNING" || echo "✗ auditd: STOPPED"
systemctl is-active rsyslog && echo "✓ rsyslog: RUNNING" || echo "✗ rsyslog: STOPPED"

# 2. Configuration validation
echo -e "\n2. Configuration Validation:"
rsyslogd -N1 >/dev/null 2>&1 && echo "✓ rsyslog config: VALID" || echo "✗ rsyslog config: INVALID"
python3 /usr/local/bin/qradar_execve_parser.py --test >/dev/null 2>&1 && echo "✓ EXECVE parser: WORKING" || echo "✗ EXECVE parser: FAILED"

# 3. Network connectivity
echo -e "\n3. Network Connectivity:"
timeout 5 bash -c "cat < /dev/null > /dev/tcp/QRADAR_IP/QRADAR_PORT" 2>/dev/null && echo "✓ QRadar connectivity: OK" || echo "✗ QRadar connectivity: FAILED"

# 4. Log generation test
echo -e "\n4. Log Generation Test:"
TEST_MSG="QRadar test $(date +%s)"
logger -p local3.info "$TEST_MSG"
sleep 3
grep -q "$TEST_MSG" /var/log/syslog 2>/dev/null && echo "✓ Local syslog: OK" || echo "✗ Local syslog: FAILED"

# 5. Audit test
echo -e "\n5. Audit Test:"
sudo touch /etc/passwd >/dev/null 2>&1
sleep 2
ausearch --start today -k identity_changes >/dev/null 2>&1 && echo "✓ Audit logging: OK" || echo "✗ Audit logging: FAILED"

echo -e "\n=== Test Complete ==="
```

---

### 2. **Monitoring Scriptleri**

#### **QRadar Health Check Script**:
```bash
#!/bin/bash
# /usr/local/bin/qradar-health-check.sh

LOG_FILE="/var/log/qradar-health.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Service check
if ! systemctl is-active --quiet auditd; then
    log "WARNING: auditd service is not running"
    systemctl start auditd
fi

if ! systemctl is-active --quiet rsyslog; then
    log "WARNING: rsyslog service is not running"
    systemctl start rsyslog
fi

# QRadar connectivity check
if ! timeout 5 bash -c "cat < /dev/null > /dev/tcp/QRADAR_IP/QRADAR_PORT" 2>/dev/null; then
    log "ERROR: Cannot connect to QRadar at QRADAR_IP:QRADAR_PORT"
else
    log "INFO: QRadar connectivity OK"
fi

# Log volume check
AUDIT_SIZE=$(du -s /var/log/audit/ | cut -f1)
if [ "$AUDIT_SIZE" -gt 1000000 ]; then  # 1GB
    log "WARNING: Audit log size is large: ${AUDIT_SIZE}KB"
fi

log "INFO: Health check completed"
```

#### **Crontab'a ekle**:
```bash
# Her saat başı health check
echo "0 * * * * root /usr/local/bin/qradar-health-check.sh" | sudo tee -a /etc/crontab
```

---

## 📞 Ek Destek ve Kaynaklar

### Detaylı Log Analizi
```bash
# Kurulum loglarını analiz et
grep -E "(ERROR|WARN|FAIL)" /var/log/qradar_*_setup.log

# Audit log performance analizi
sudo aureport --summary

# Rsyslog statistics
sudo rsyslogd -N1 | grep -i error
```

### Yapılandırma Backup/Restore
```bash
# Current config backup
sudo tar -czf qradar-config-backup-$(date +%Y%m%d).tar.gz \
    /etc/audit/rules.d/99-qradar.rules \
    /etc/rsyslog.d/99-qradar.conf \
    /etc/audit*/plugins.d/syslog.conf \
    /usr/local/bin/qradar_execve_parser.py

# Restore from backup
sudo tar -xzf qradar-config-backup-YYYYMMDD.tar.gz -C /
sudo systemctl restart auditd rsyslog
```

### İletişim ve Destek
- **GitHub Issues**: [QRadar Log Forwarding Issues](https://github.com/00gxd14g/QRadar_Log_Forwarding/issues)
- **Dokümantasyon**: [Ana README](README.md)
- **Script Fonksiyonları**: [SCRIPT_FONKSIYONLARI.md](SCRIPT_FONKSIYONLARI.md)

---

**Bu sorun giderme kılavuzu düzenli olarak güncellenmektedir. Yeni sorunlar ve çözümler için GitHub repository'sini takip edin.**