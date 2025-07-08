# QRadar Log Forwarding - Manuel Düzeltme Adımları

Bu dokümanda, QRadar log forwarding script'inde tespit edilen sorunlar ve manuel olarak yapılması gereken düzeltmeler yer almaktadır.

## RHEL 7 Sistemlerde Manuel Düzeltmeler

### 1. audisp-syslog Binary Sorunu
**Sorun:** audisp-syslog binary'si bulunamıyor
**Çözüm:**
```bash
# audispd-plugins paketini yükle
sudo yum install -y audispd-plugins

# Binary'nin yerini kontrol et
ls -la /sbin/audisp-syslog
```

### 2. EPEL Repository Sorunu
**Sorun:** EPEL repository kurulumu başarısız oluyor
**Çözüm:**
```bash
# EPEL repository'yi manuel olarak yükle
sudo yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

# Alternatif olarak direkt python3 yükle
sudo yum install -y python3
```

### 3. Python3 Path Sorunu
**Sorun:** Python3 yüklü olmasına rağmen path bulunamıyor
**Çözüm:**
```bash
# Python3 binary'sinin yerini kontrol et
which python3
ls -la /usr/bin/python3*

# Symlink oluştur (gerekirse)
sudo ln -sf /usr/bin/python36 /usr/bin/python3
```

## RHEL 8 Sistemlerde Manuel Düzeltmeler

### 1. Audit Rules Syntax Sorunu
**Sorun:** "Error - nested rule files not supported"
**Çözüm:**
```bash
# Mevcut audit kurallarını temizle
sudo auditctl -D

# Kuralları manuel olarak yükle
sudo auditctl -R /etc/audit/rules.d/qradar.rules

# Alternatif: Kuralları tek tek yükle
while IFS= read -r line; do
    if [[ "$line" =~ ^-[abwWe] ]]; then
        sudo auditctl $line
    fi
done < /etc/audit/rules.d/qradar.rules
```

### 2. Auditd Service Management Sorunu
**Sorun:** "Operation refused, unit auditd.service may be requested by dependency only"
**Çözüm:**
```bash
# RHEL 8'de auditd için service komutu kullan
sudo service auditd restart

# Status kontrol et
sudo systemctl status auditd
```

### 3. Audit Events Syslog'a Ulaşmıyor
**Sorun:** Audit eventleri syslog'a ulaşmıyor
**Çözüm:**
```bash
# audisp-syslog plugin'ini kontrol et
sudo cat /etc/audit/plugins.d/syslog.conf

# Rsyslog yapılandırmasını kontrol et
sudo rsyslogd -N1 -f /etc/rsyslog.d/10-qradar.conf

# Servisleri yeniden başlat
sudo service auditd restart
sudo systemctl restart rsyslog

# Test et
logger -p local3.info "Test message"
tail -f /var/log/messages | grep "Test message"
```

### 4. Manual Rule Loading (RHEL 8 için özel)
**Sorun:** augenrules çalışmıyor
**Çözüm:**
```bash
# Script düzeltmesi sonrası otomatik olarak çözüldü
# Eğer hala sorun varsa manuel yükleme:

# Tüm kuralları temizle
sudo auditctl -D

# Ana audit dosyasını kontrol et
sudo cat /etc/audit/audit.rules

# Kuralları manuel yükle
sudo auditctl -w /etc/passwd -p wa -k identity_changes
sudo auditctl -w /etc/shadow -p wa -k identity_changes
sudo auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
# ... diğer kurallar
```

## Genel Sorun Giderme Adımları

### 1. Log Dosyalarını Kontrol Et
```bash
# Ana setup log'unu kontrol et
sudo tail -f /var/log/qradar_setup.log

# Audit log'larını kontrol et
sudo tail -f /var/log/audit/audit.log

# Syslog mesajlarını kontrol et
sudo tail -f /var/log/messages
```

### 2. Servis Statuslarını Kontrol Et
```bash
# Servislerin durumunu kontrol et
sudo systemctl status auditd
sudo systemctl status rsyslog

# Servisleri yeniden başlat
sudo service auditd restart  # RHEL 8 için
sudo systemctl restart rsyslog
```

### 3. Network Connectivity Test
```bash
# QRadar bağlantısını test et
telnet <QRADAR_IP> <QRADAR_PORT>

# Alternatif test
nc -zv <QRADAR_IP> <QRADAR_PORT>

# Log gönderme testi
logger -p local3.info "QRadar test message $(date)"
```

### 4. Firewall ve SELinux Kontrolleri
```bash
# Firewall durumunu kontrol et
sudo firewall-cmd --list-all

# SELinux durumunu kontrol et
getenforce
sudo setsebool -P rsyslogd_can_network_connect on

# SELinux context'i düzelt
sudo restorecon -R /usr/local/bin/concat_execve.py
```

## Script Sonrası Doğrulama

### 1. Audit Rules Kontrolü
```bash
# Yüklenen kuralları listele
sudo auditctl -l

# Kural sayısını kontrol et
sudo auditctl -s
```

### 2. Log Forwarding Testi
```bash
# Test mesajı gönder
logger -p local3.info "QRadar forwarding test $(date)"

# Audit event oluştur
touch /etc/passwd

# QRadar'da logların ulaştığını kontrol et
```

### 3. Python Script Testi
```bash
# Concatenation script'ini test et
echo 'audit(1234567890.123:456): arch=c000003e syscall=59 success=yes exit=0 a0="ls" a1="-la" a2="/home" type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="ls" a1="-la" a2="/home"' | /usr/local/bin/concat_execve.py
```

## Kritik Notlar

1. **RHEL 8'de auditd service management özeldir** - systemctl yerine service komutu kullanın
2. **Audit rules syntax RHEL 8'de farklıdır** - augenrules yerine auditctl kullanın  
3. **audisp-syslog RHEL 7'de ek paket gerektirir** - audispd-plugins paketini yükleyin
4. **SELinux aktifse ek yapılandırma gerekir** - rsyslogd_can_network_connect boolean'ını aktifleştirin
5. **Network connectivity kritiktir** - QRadar erişilebilir olmalı

Bu adımları takip ederek script'in çalışmadığı durumlarda manuel olarak yapılandırmayı tamamlayabilirsiniz.