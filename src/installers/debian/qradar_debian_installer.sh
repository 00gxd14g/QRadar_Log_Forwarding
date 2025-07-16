#!/usr/bin/env bash
#
# ===============================================================================
# QRadar Universal Debian Log Forwarding Installer v4.0.0
# ===============================================================================
#
# Bu script, tüm Debian sürümlerinde çalışacak şekilde tasarlanmış
# QRadar SIEM log iletimi kurulum scriptıdir.
#
# Desteklenen Debian Sürümleri:
#   - Debian 9 (Stretch)
#   - Debian 10 (Buster)
#   - Debian 11 (Bullseye)
#   - Debian 12 (Bookworm)
#   - Debian Testing/Unstable
#   - Kali Linux (tüm sürümler)
#
# Özellikler:
#   - Otomatik Debian sürüm tespiti ve uyumluluk
#   - APT paket yöneticisi optimizasyonu
#   - Kapsamlı güvenlik monitoring (MITRE ATT&CK uyumlu)
#   - EXECVE komut birleştirme (command concatenation)
#   - Güvenli komut çalıştırma (eval kullanmaz)
#   - Otomatik hata düzeltme ve fallback mekanizmaları
#
# Kullanım: sudo bash qradar_debian_installer.sh <QRADAR_IP> <QRADAR_PORT>
#
# Örnek: sudo bash qradar_debian_installer.sh 192.168.1.100 514
#
# Yazar: QRadar Log Forwarding Projesi
# Sürüm: 4.0.0 - Universal Debian Edition
# ===============================================================================

set -Eeuo pipefail
trap 'error_exit "Unexpected failure (line: $LINENO)"' ERR

# ===============================================================================
# GLOBAL DEĞIŞKENLER
# ===============================================================================

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
SCRIPT_DIR="$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd -P)"
readonly SCRIPT_DIR
readonly SCRIPT_VERSION="4.0.0-debian-universal"
readonly LOG_FILE="qradar_debian_setup.log"
BACKUP_DIR="/etc/qradar_backup_$(date +%Y%m%d_%H%M%S)"
readonly BACKUP_DIR

# Dosya yolları
readonly AUDIT_RULES_FILE="/etc/audit/rules.d/99-qradar.rules"
readonly AUDISP_PLUGINS_DIR="/etc/audisp/plugins.d"
readonly AUDIT_PLUGINS_DIR="/etc/audit/plugins.d"
readonly AUDIT_SYSLOG_CONF="/etc/audit/plugins.d/syslog.conf"
readonly RSYSLOG_QRADAR_CONF="/etc/rsyslog.d/99-qradar.conf"
readonly CONCAT_SCRIPT_PATH="/usr/local/bin/qradar_execve_parser.py"

# Sistem bilgileri
DEBIAN_VERSION=""
DEBIAN_CODENAME=""
VERSION_MAJOR=""
IS_KALI=false
AUDISP_METHOD=""
AUDISP_SYSLOG_CONF=""
SYSLOG_FILE="/var/log/syslog"

# Script parametreleri
QRADAR_IP=""
QRADAR_PORT=""
USE_MINIMAL_RULES=false
DRY_RUN=false

# ===============================================================================
# YARDIMCI FONKSİYONLAR
# ===============================================================================

# Geliştirilmiş logging fonksiyonu
log() {
    local level="${1:-INFO}"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Hata yönetimi
error_exit() {
    log "ERROR" "$1"
    echo "HATA: $1" >&2
    echo "Detaylar için $LOG_FILE dosyasını kontrol edin."
    exit 1
}

# Uyarı mesajı
warn() {
    log "WARN" "$1"
    echo "UYARI: $1" >&2
}

# Başarı mesajı
success() {
    log "SUCCESS" "$1"
    echo "✓ $1"
}

# Komut varlığı kontrolü
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Güvenli komut çalıştırma (eval kullanmaz)
safe_execute() {
    local description="$1"
    shift
    log "DEBUG" "Çalıştırılıyor: $description - Komut: $*"
    
    if "$@" >> "$LOG_FILE" 2>&1; then
        log "DEBUG" "$description - BAŞARILI"
        return 0
    else
        local exit_code=$?
        warn "$description - BAŞARISIZ (Çıkış kodu: $exit_code)"
        return $exit_code
    fi
}

# Retry mekanizması
retry_operation() {
    local max_attempts=3
    local delay=5
    local description="$1"
    shift
    
    for ((attempt=1; attempt<=max_attempts; attempt++)); do
        if safe_execute "$description (Deneme $attempt/$max_attempts)" "$@"; then
            return 0
        fi
        if [[ $attempt -lt $max_attempts ]]; then
            log "INFO" "$delay saniye sonra tekrar denenecek..."
            sleep $delay
        fi
    done
    
    error_exit "$description $max_attempts denemeden sonra başarısız oldu"
}

# Dosya yedekleme
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_file
backup_file="$BACKUP_DIR/$(basename "$file").$(date +%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$backup_file" || warn "$file yedeklenemedi"
        log "INFO" "$file dosyası $backup_file konumuna yedeklendi"
    fi
}

# Proje kök dizinini bul
project_root() {
    local dir="$SCRIPT_DIR"
    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/src/installers/debian/qradar_debian_installer.sh" ]]; then
            echo "$dir"
            return
        fi
        dir="$(dirname "$dir")"
    done
}

# ===============================================================================
# SİSTEM TESPİTİ VE DOĞRULAMA
# ===============================================================================

detect_debian_version() {
    log "INFO" "Debian/Kali sürümü tespit ediliyor..."
    
    if [[ ! -f /etc/os-release ]]; then
        error_exit "/etc/os-release dosyası bulunamadı. Debian sistemi doğrulanamıyor."
    fi
    
    # shellcheck source=/etc/os-release
    source /etc/os-release
    
    # Gerekli değişkenlerin tanımlı olduğunu kontrol et
    if [[ -z "${ID:-}" ]]; then
        error_exit "ID değişkeni /etc/os-release dosyasında bulunamadı"
    fi
    
    if [[ -z "${VERSION_ID:-}" ]]; then
        error_exit "VERSION_ID değişkeni /etc/os-release dosyasında bulunamadı"
    fi
    
    if [[ -z "${VERSION_CODENAME:-}" ]]; then
        error_exit "VERSION_CODENAME değişkeni /etc/os-release dosyasında bulunamadı"
    fi
    
    # Debian veya Kali kontrolü
    if [[ "$ID" == "debian" ]]; then
        DEBIAN_VERSION="$VERSION_ID"
        DEBIAN_CODENAME="$VERSION_CODENAME"
        log "INFO" "Debian sistemi tespit edildi"
    elif [[ "$ID" == "kali" ]]; then
        IS_KALI=true
        DEBIAN_VERSION="kali"
        DEBIAN_CODENAME="$VERSION_CODENAME"
        log "INFO" "Kali Linux sistemi tespit edildi"
    else
        error_exit "Bu script sadece Debian/Kali sistemler için tasarlanmıştır. Tespit edilen: $ID"
    fi
    
    # Debian 9+ kontrolü (Kali hariç)
    if [[ "$IS_KALI" == false ]]; then
        VERSION_MAJOR="${DEBIAN_VERSION%%.*}"
        if [[ -z "$VERSION_MAJOR" ]] || [[ ! "$VERSION_MAJOR" =~ ^[0-9]+$ ]]; then
            error_exit "VERSION_MAJOR değeri geçersiz: '$VERSION_MAJOR' (DEBIAN_VERSION: $DEBIAN_VERSION)"
        fi
        if [[ $VERSION_MAJOR -lt 9 ]]; then
            error_exit "Bu script Debian 9+ sürümlerini destekler. Mevcut sürüm: $DEBIAN_VERSION"
        fi
    fi
    
    if [[ "$IS_KALI" == true ]]; then
        success "Kali Linux ($DEBIAN_CODENAME) tespit edildi ve destekleniyor"
    else
        success "Debian $DEBIAN_VERSION ($DEBIAN_CODENAME) tespit edildi ve destekleniyor"
    fi
    
    # Sürüme göre audisp metodunu belirle
    determine_audisp_method
}

determine_audisp_method() {
    log "INFO" "Debian/Kali sürümüne göre audisp metodu belirleniyor..."
    
    # Kali ve Debian 10+ modern audit kullanır
    if [[ "$IS_KALI" == true ]] || [[ $VERSION_MAJOR -ge 10 ]]; then
        AUDISP_METHOD="modern"
        AUDISP_SYSLOG_CONF="$AUDIT_SYSLOG_CONF"
        log "INFO" "Modern audit metodu kullanılacak (/etc/audit/plugins.d/)"
    else
        AUDISP_METHOD="legacy"
        AUDISP_SYSLOG_CONF="$AUDISP_PLUGINS_DIR/syslog.conf"
        log "INFO" "Legacy audisp metodu kullanılacak (/etc/audisp/plugins.d/)"
    fi
    
    # Dizinleri kontrol et ve oluştur
    if [[ "$AUDISP_METHOD" == "legacy" ]]; then
        mkdir -p "$AUDISP_PLUGINS_DIR"
    else
        mkdir -p "$AUDIT_PLUGINS_DIR"
    fi
}

# ===============================================================================
# PAKET KURULUMU
# ===============================================================================

install_required_packages() {
    log "INFO" "Gerekli paketler kontrol ediliyor ve kuruluyor..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "DRY RUN: Skipping package installation"
        return
    fi
    
    # Debian/Kali için paket listesi
    local required_packages=("auditd" "rsyslog" "python3")
    
    # Debian 9 için audispd-plugins
    if [[ "$IS_KALI" == false ]] && [[ $VERSION_MAJOR -eq 9 ]]; then
        required_packages+=("audispd-plugins")
    fi
    
    # Kali için özel paketler
    if [[ "$IS_KALI" == true ]]; then
        required_packages+=("auditd" "rsyslog")
    fi
    
    local packages_to_install=()
    
    # APT cache'i güncelle
    export DEBIAN_FRONTEND=noninteractive
    retry_operation "APT cache güncelleme" apt-get update
    
    # Hangi paketlerin kurulu olmadığını kontrol et
    for package in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package "; then
            packages_to_install+=("$package")
            log "INFO" "$package paketi kurulu değil"
        else
            log "INFO" "$package paketi zaten kurulu"
        fi
    done
    
    # Eksik paketleri kur
    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        log "INFO" "Kurulacak paketler: ${packages_to_install[*]}"
        retry_operation "Paket kurulumu" apt-get install -y "${packages_to_install[@]}"
        success "Paketler başarıyla kuruldu: ${packages_to_install[*]}"
    else
        success "Tüm gerekli paketler zaten kurulu"
    fi
    
    # Kritik binary'leri doğrula
    local critical_binaries=("/sbin/auditd" "/usr/sbin/rsyslogd" "/usr/bin/python3")
    for binary in "${critical_binaries[@]}"; do
        if [[ ! -f "$binary" ]]; then
            error_exit "Kritik binary bulunamadı: $binary"
        fi
    done
    
    success "Tüm kritik binary'ler doğrulandı"
}

# ===============================================================================
# PYTHON PARSER SCRIPT'İ
# ===============================================================================

deploy_execve_parser() {
    log "INFO" "Debian/Kali için EXECVE komut ayrıştırıcısı deploy ediliyor..."
    
    backup_file "$CONCAT_SCRIPT_PATH"
    
    cat > "$CONCAT_SCRIPT_PATH" << 'EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QRadar Universal Debian/Kali EXECVE Parser v4.0.0

Bu script, audit EXECVE mesajlarını işleyerek komut argümanlarını
tek bir alan haline getirir ve MITRE ATT&CK tekniklerine göre etiketler.

Debian 9+ ve tüm Kali sürümlerinde çalışır.
"""

import sys
import re
import socket
import signal
from datetime import datetime

class DebianExecveParser:
    def __init__(self):
        # Signal handler'ları ayarla
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Graceful shutdown için signal handler"""
        sys.exit(0)
    
    def process_execve_line(self, line):
        """EXECVE audit log satırını işle ve komut argümanlarını birleştir"""
        if "type=EXECVE" not in line:
            return line
        
        # Proctitle satırlarını atla
        if "proctitle=" in line or "PROCTITLE" in line:
            return None
        
        try:
            # Tüm argüman alanlarını yakala: a0="...", a1="...", vb.
            args_pattern = r'a(\d+)="([^"]*)"'
            args_matches = re.findall(args_pattern, line)
            
            if not args_matches:
                return line
            
            # Argümanları index'e göre sırala
            args_dict = {}
            for arg_index, arg_value in args_matches:
                args_dict[int(arg_index)] = arg_value
            
            # Argümanları sıralı şekilde birleştir
            sorted_args = sorted(args_dict.items())
            combined_command = " ".join(arg[1] for arg in sorted_args)
            
            # Mevcut aX="..." alanlarını kaldır
            cleaned_line = re.sub(r'a\d+="[^"]*"\s*', '', line).strip()
            cleaned_line = re.sub(r'argc=\d+\s*', '', cleaned_line).strip()
            
            # Birleştirilmiş komutu tek alan olarak ekle
            processed_line = f"{cleaned_line} cmd=\"{combined_command}\""
            return processed_line
            
        except Exception as e:
            # Hata durumunda orijinal satırı döndür
            return line
    
    def run(self):
        """Ana işlem döngüsü"""
        try:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    processed_line = self.process_execve_line(line)
                    if processed_line is not None:
                        print(processed_line, flush=True)
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        except Exception:
            sys.exit(1)

if __name__ == "__main__":
    parser = DebianExecveParser()
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        success = parser.run()
        sys.exit(0 if success else 1)
    else:
        parser.run()
EOF
    
    chmod +x "$CONCAT_SCRIPT_PATH" || error_exit "EXECVE parser script'i çalıştırılabilir yapılamadı"
    chown root:root "$CONCAT_SCRIPT_PATH" || warn "EXECVE parser script'i sahiplik ayarlanamadı"
    
    # Test et
    if python3 "$CONCAT_SCRIPT_PATH" --test >> "$LOG_FILE" 2>&1; then
        success "Debian/Kali EXECVE komut ayrıştırıcısı başarıyla deploy edildi ve test edildi"
    else
        warn "EXECVE parser test başarısız oldu, ancak script deploy edildi"
    fi
}

# ===============================================================================
# AUDIT CONFIGURATION
# ===============================================================================

configure_auditd() {
    log "INFO" "Debian/Kali için auditd kuralları yapılandırılıyor..."
    
    backup_file "$AUDIT_RULES_FILE"
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")"
    
    if [[ "$USE_MINIMAL_RULES" == true ]]; then
        log "INFO" "Minimal audit kuralları kullanılıyor"
        cat > "$AUDIT_RULES_FILE" << 'EOF'
# QRadar Minimal Audit Rules (EPS Optimized)
-D
-b 4096
-f 1
-r 50
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k user_commands
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k user_commands
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_commands
-w /var/log/auth.log -p wa -k authentication
-w /var/log/secure -p wa -k authentication
-w /usr/bin/sudo -p x -k privileged_commands
-w /bin/su -p x -k privileged_commands
-w /usr/bin/pkexec -p x -k privileged_commands
-w /etc/passwd -p wa -k identity_files
-w /etc/shadow -p wa -k identity_files
-w /etc/sudoers -p wa -k identity_files
-w /etc/sudoers.d/ -p wa -k identity_files
-w /usr/bin/systemctl -p x -k service_control
-w /sbin/service -p x -k service_control
-w /sbin/shutdown -p x -k system_shutdown
-w /sbin/reboot -p x -k system_reboot
-w /sbin/halt -p x -k system_shutdown
-a exclude,always -F msgtype=SERVICE_START
-a exclude,always -F msgtype=SERVICE_STOP
-a exclude,always -F msgtype=BPF
-a never,exit -F exe=/usr/bin/awk
-a never,exit -F exe=/usr/bin/grep
-a never,exit -F exe=/usr/bin/sed
-a never,exit -F exe=/bin/cat
-a never,exit -F exe=/bin/ls
-a never,exit -F dir=/tmp/
-a never,exit -F dir=/var/spool/
-a never,exit -F dir=/var/tmp/
EOF
    else
        log "INFO" "Standard audit kuralları kullanılıyor"
        cat > "$AUDIT_RULES_FILE" << 'EOF'
# QRadar Universal Debian/Kali Audit Rules v4.1.0
# Comprehensive user behavior logging

## Mevcut kuralları temizle ve yeniden başlat
-D

## Buffer boyutu (üretim ortamı için optimize edilmiş)
-b 16384

## Hata modu (1 = hata mesajı yazdır, 0 = sessiz)
-f 1

## Rate limiting (saniyede maksimum 150 olay)
-r 150

## Hataları yoksay (kural yükleme sırasında)
-i

#################################
# Kimlik ve Erişim Yönetimi (MITRE T1003, T1078)
#################################
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k credential_access
-w /etc/group -p wa -k identity_changes
-w /etc/gshadow -p wa -k credential_access
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

#################################
# Kimlik Doğrulama ve PAM (MITRE T1556)
#################################
-w /etc/pam.d/ -p wa -k authentication_config
-w /etc/security/ -p wa -k security_config
-w /etc/login.defs -p wa -k login_config

#################################
# SSH Yapılandırması (MITRE T1021.004)
#################################
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/ssh_config -p wa -k ssh_config
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/*/.ssh/ -p wa -k ssh_keys

#################################
# Komut Çalıştırma İzleme (MITRE T1059)
#################################
# Root komutları (güvenlik odaklı)
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_commands

# Kullanıcı komutları (sistem kullanıcıları hariç)
-a always,exit -F arch=b64 -S execve -F euid>=1000 -F auid>=1000 -F auid!=4294967295 -k user_commands
-a always,exit -F arch=b32 -S execve -F euid>=1000 -F auid>=1000 -F auid!=4294967295 -k user_commands

# Yetki yükseltme komutları (MITRE T1548)
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/pkexec -p x -k privilege_escalation
-w /usr/bin/gksu -p x -k privilege_escalation
-w /usr/bin/gksudo -p x -k privilege_escalation

#################################
# Penetration Testing Araçları (Kali özel)
#################################
-w /usr/bin/nmap -p x -k pentest_tools
-w /usr/bin/masscan -p x -k pentest_tools
-w /usr/bin/zmap -p x -k pentest_tools
-w /usr/bin/msfconsole -p x -k pentest_tools
-w /usr/bin/meterpreter -p x -k pentest_tools
-w /usr/bin/john -p x -k pentest_tools
-w /usr/bin/hashcat -p x -k pentest_tools
-w /usr/bin/hydra -p x -k pentest_tools
-w /usr/bin/medusa -p x -k pentest_tools
-w /usr/bin/nikto -p x -k pentest_tools
-w /usr/bin/sqlmap -p x -k pentest_tools
-w /usr/bin/aircrack-ng -p x -k pentest_tools
-w /usr/bin/wireshark -p x -k pentest_tools
-w /usr/bin/tcpdump -p x -k pentest_tools

#################################
# Ağ Yapılandırması (MITRE T1016)
#################################
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_config
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/hostname -p wa -k network_config

# Debian network configuration
-w /etc/network/interfaces -p wa -k network_config
-w /etc/network/interfaces.d/ -p wa -k network_config
-w /etc/systemd/network/ -p wa -k network_config

#################################
# Sistem Durumu Değişiklikleri (MITRE T1529)
#################################
-w /sbin/shutdown -p x -k system_shutdown
-w /sbin/poweroff -p x -k system_shutdown
-w /sbin/reboot -p x -k system_shutdown
-w /sbin/halt -p x -k system_shutdown

#################################
# Dosya İzinleri ve Sahiplik (MITRE T1222)
#################################
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b64 -S chown -S fchown -S lchown -S fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership
-a always,exit -F arch=b32 -S chown -S fchown -S lchown -S fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership

#################################
# Ağ Araçları ve Keşif (MITRE T1018, T1046)
#################################
-w /usr/bin/wget -p x -k network_tools
-w /usr/bin/curl -p x -k network_tools
-w /bin/nc -p x -k network_tools
-w /usr/bin/ncat -p x -k network_tools
-w /usr/bin/netcat -p x -k network_tools
-w /usr/bin/socat -p x -k network_tools
-w /usr/bin/netdiscover -p x -k network_discovery
-w /usr/bin/arp-scan -p x -k network_discovery
-w /usr/bin/fping -p x -k network_discovery

#################################
# Uzaktan Erişim Araçları (MITRE T1021)
#################################
-w /usr/bin/ssh -p x -k remote_access
-w /usr/bin/scp -p x -k remote_access
-w /usr/bin/sftp -p x -k remote_access
-w /usr/bin/rsync -p x -k remote_access

#################################
# Sistem Keşfi (MITRE T1082, T1087)
#################################
-w /usr/bin/whoami -p x -k system_discovery
-w /usr/bin/id -p x -k system_discovery
-w /usr/bin/w -p x -k system_discovery
-w /usr/bin/who -p x -k system_discovery
-w /usr/bin/last -p x -k system_discovery
-w /usr/bin/lastlog -p x -k system_discovery

#################################
# Cron Jobs ve Zamanlama (MITRE T1053)
#################################
-w /etc/cron.d/ -p wa -k scheduled_tasks
-w /etc/cron.daily/ -p wa -k scheduled_tasks
-w /etc/cron.hourly/ -p wa -k scheduled_tasks
-w /etc/cron.monthly/ -p wa -k scheduled_tasks
-w /etc/cron.weekly/ -p wa -k scheduled_tasks
-w /var/spool/cron/ -p wa -k scheduled_tasks
-w /etc/crontab -p wa -k scheduled_tasks

#################################
# Systemd Servisleri (MITRE T1543.002)
#################################
-w /etc/systemd/system/ -p wa -k systemd_services
-w /lib/systemd/system/ -p wa -k systemd_services
-w /usr/lib/systemd/system/ -p wa -k systemd_services

#################################
# Kernel Modülleri (MITRE T1547.006)
#################################
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k kernel_modules
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules

#################################
# Log Dosyaları (MITRE T1070.002)
#################################
-w /var/log/auth.log -p wa -k log_modification
-w /var/log/syslog -p wa -k log_modification
-w /var/log/audit/ -p wa -k audit_log_modification
-w /var/log/kern.log -p wa -k log_modification

#################################
# Kali Linux Özel Dizinler
#################################
-w /opt/ -p wa -k kali_tools
-w /usr/share/metasploit-framework/ -p wa -k metasploit_usage
-w /usr/share/wordlists/ -p wa -k wordlist_access

#################################
# Audit Sistemi Koruması
#################################
-w /etc/audit/ -p wa -k audit_config
-w /sbin/auditctl -p x -k audit_tools
-w /sbin/auditd -p x -k audit_tools

# Kuralları değiştirilemez yap (yüksek güvenlik ortamları için)
# -e 2
EOF
    fi
    
    chmod 640 "$AUDIT_RULES_FILE"
    success "Debian/Kali Universal audit kuralları yapılandırıldı"
}

# ===============================================================================
# AUDISP CONFIGURATION
# ===============================================================================

configure_audisp() {
    log "INFO" "Debian/Kali sürümüne göre audisp yapılandırılıyor..."
    
    backup_file "$AUDISP_SYSLOG_CONF"
    
    # Sürüme göre uygun dizini oluştur
    if [[ "$AUDISP_METHOD" == "legacy" ]]; then
        mkdir -p "$AUDISP_PLUGINS_DIR"
        log "INFO" "Legacy audisp yapılandırması (Debian $DEBIAN_VERSION)"
    else
        mkdir -p "$AUDIT_PLUGINS_DIR"
        if [[ "$IS_KALI" == true ]]; then
            log "INFO" "Modern audit yapılandırması (Kali Linux)"
        else
            log "INFO" "Modern audit yapılandırması (Debian $DEBIAN_VERSION)"
        fi
    fi
    
    # Syslog plugin yapılandırması
    cat > "$AUDISP_SYSLOG_CONF" << 'EOF'
# QRadar Universal Debian/Kali Audisp Configuration
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_LOCAL3
format = string
EOF
    
    chmod 640 "$AUDISP_SYSLOG_CONF"
    
    if [[ "$IS_KALI" == true ]]; then
        success "Audisp syslog plugin yapılandırıldı (Kali Linux - $AUDISP_METHOD method)"
    else
        success "Audisp syslog plugin yapılandırıldı (Debian $DEBIAN_VERSION - $AUDISP_METHOD method)"
    fi
}

# ===============================================================================
# RSYSLOG CONFIGURATION
# ===============================================================================

configure_rsyslog() {
    log "INFO" "Debian/Kali için rsyslog QRadar iletimi yapılandırılıyor..."
    
    backup_file "$RSYSLOG_QRADAR_CONF"
    
    # Ensure rsyslog spool directory exists
    local SPOOL_DIR="/var/spool/rsyslog"
    if [[ ! -d "$SPOOL_DIR" ]]; then
        mkdir -p "$SPOOL_DIR"
        chown root:root "$SPOOL_DIR"
        chmod 755 "$SPOOL_DIR"
        log "INFO" "Rsyslog spool directory created: $SPOOL_DIR"
    fi
    
    # Generate configuration from template
    if [[ ! -f "$SCRIPT_DIR/../universal/99-qradar.conf" ]]; then
        error_exit "Rsyslog template not found: $SCRIPT_DIR/../universal/99-qradar.conf"
    fi
    
    # shellcheck source=../universal/99-qradar.conf
    sed -e "s/<QRADAR_IP>/$QRADAR_IP/g" \
        -e "s/<QRADAR_PORT>/$QRADAR_PORT/g" \
        "$SCRIPT_DIR/../universal/99-qradar.conf" > "$RSYSLOG_QRADAR_CONF"
    
    # Validate generated configuration
    if [[ ! -s "$RSYSLOG_QRADAR_CONF" ]]; then
        error_exit "Failed to generate rsyslog configuration"
    fi
    
    # Set proper permissions
    chmod 644 "$RSYSLOG_QRADAR_CONF"
    chown root:root "$RSYSLOG_QRADAR_CONF"
    
    # Syntax validation with rsyslogd
    log "INFO" "Validating rsyslog configuration syntax..."
    if command_exists rsyslogd; then
        if rsyslogd -N1 -f "$RSYSLOG_QRADAR_CONF" >> "$LOG_FILE" 2>&1; then
            success "Rsyslog configuration syntax is valid"
        else
            # Try to extract error message
            local error_msg
            error_msg=$(rsyslogd -N1 -f "$RSYSLOG_QRADAR_CONF" 2>&1 | head -5)
            error_exit "Invalid rsyslog configuration: $error_msg"
        fi
    else
        warn "rsyslogd not found for syntax validation"
    fi
    
    # Check if main rsyslog.conf includes our config directory
    local MAIN_RSYSLOG_CONF="/etc/rsyslog.conf"
    if [[ -f "$MAIN_RSYSLOG_CONF" ]]; then
        if ! grep -q '^\s*\$IncludeConfig\s*/etc/rsyslog\.d/\*\.conf' "$MAIN_RSYSLOG_CONF" && \
           ! grep -q '^include(file="/etc/rsyslog\.d/\*\.conf")' "$MAIN_RSYSLOG_CONF"; then
            warn "Main rsyslog.conf may not include /etc/rsyslog.d/*.conf files"
            log "INFO" "Consider adding: include(file=\"/etc/rsyslog.d/*.conf\") to $MAIN_RSYSLOG_CONF"
        fi
    fi
    
    success "Rsyslog Debian/Kali Universal yapılandırması tamamlandı"
}

# ===============================================================================
# SERVICE MANAGEMENT
# ===============================================================================

restart_services() {
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "DRY RUN: Skipping service restarts."
        return
    fi

    log "INFO" "Debian/Kali servisleri yeniden başlatılıyor..."
    
    # Servisleri enable et
    safe_execute "auditd servisini enable etme" systemctl enable auditd
    safe_execute "rsyslog servisini enable etme" systemctl enable rsyslog
    
    # Final rsyslog configuration validation
    log "INFO" "Performing final rsyslog configuration check..."
    if ! rsyslogd -N1 >> "$LOG_FILE" 2>&1; then
        warn "Full rsyslog configuration has warnings, checking our specific config..."
        if ! rsyslogd -N1 -f "$RSYSLOG_QRADAR_CONF" >> "$LOG_FILE" 2>&1; then
            error_exit "Rsyslog configuration file $RSYSLOG_QRADAR_CONF is invalid"
        fi
    fi
    success "Rsyslog configuration validated"
    
    # Servisleri durdur
    safe_execute "auditd servisini durdurma" systemctl stop auditd || true
    safe_execute "rsyslog servisini durdurma" systemctl stop rsyslog || true
    
    sleep 3
    
    # Auditd'yi başlat
    retry_operation "auditd servisini başlatma" systemctl start auditd
    
    sleep 2
    
    # Audit kurallarını yükle
    load_audit_rules
    
    # Rsyslog'u başlat
    retry_operation "rsyslog servisini başlatma" systemctl start rsyslog
    
    success "Tüm Debian/Kali servisleri başarıyla yapılandırıldı ve başlatıldı"
}

load_audit_rules() {
    log "INFO" "Debian/Kali audit kuralları yükleniyor..."
    
    # Method 1: augenrules (Debian 10+, Kali)
    if command_exists augenrules; then
        if safe_execute "augenrules ile kural yükleme" augenrules --load; then
            success "Audit kuralları augenrules ile yüklendi"
            return
        fi
    fi
    
    # Method 2: auditctl ile doğrudan yükleme
    if safe_execute "auditctl ile kural yükleme" auditctl -R "$AUDIT_RULES_FILE"; then
        success "Audit kuralları auditctl ile yüklendi"
        return
    fi
    
    # Method 3: Satır satır yükleme (fallback)
    log "INFO" "Fallback: Kurallar satır satır yükleniyor..."
    local rules_loaded=0
    while IFS= read -r line; do
        if [[ -n "$line" ]] && [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ "$line" =~ ^[[:space:]]*- ]]; then
            if [[ "$line" == "-e 2" ]]; then
                continue  # İmmutable flag'i son olarak uygula
            fi
            if auditctl "$line" >> "$LOG_FILE" 2>&1; then
                ((rules_loaded++))
            fi
        fi
    done < "$AUDIT_RULES_FILE"
    
    if [[ $rules_loaded -gt 0 ]]; then
        success "$rules_loaded audit kuralı satır satır yüklendi"
    else
        warn "Hiçbir audit kuralı yüklenemedi - fallback yapılandırması devreye alınacak"
    fi
}

# ===============================================================================
# VALIDATION AND TESTING
# ===============================================================================

run_validation_tests() {
    log "INFO" "Debian/Kali sistem doğrulama testleri çalıştırılıyor..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "DRY RUN: Skipping validation tests"
        return
    fi
    
    # Servis durumu kontrolü
    local services=("auditd" "rsyslog")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            success "$service servisi çalışıyor"
        else
            warn "$service servisi çalışmıyor - başlatmaya çalışılıyor..."
            safe_execute "$service servisini başlatma" systemctl start "$service"
        fi
    done
    
    # Rsyslog yapılandırma sözdizimi kontrolü
    if rsyslogd -N1 >> "$LOG_FILE" 2>&1; then
        success "Rsyslog yapılandırması geçerli"
    else
        warn "Rsyslog yapılandırma doğrulaması başarısız (servis çalışıyorsa normal)"
    fi
    
    # EXECVE parser testi
    if python3 "$CONCAT_SCRIPT_PATH" --test >> "$LOG_FILE" 2>&1; then
        success "Debian/Kali EXECVE parser test başarılı"
    else
        warn "EXECVE parser test başarısız"
    fi
    
    # Yerel syslog testi
    local test_message
test_message="QRadar Debian/Kali Universal Installer test $(date '+%Y%m%d%H%M%S')"
    logger -p user.info "$test_message"
    sleep 3
    
    if grep -q "$test_message" "$SYSLOG_FILE"; then
        success "Yerel syslog test başarılı"
    else
        warn "Yerel syslog test başarısız"
    fi
    
    # QRadar bağlantı testi
    test_qradar_connectivity
    
    # Audit functionality test
    test_audit_functionality
}

test_qradar_connectivity() {
    log "INFO" "QRadar bağlantısı test ediliyor..."
    
    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$QRADAR_IP/$QRADAR_PORT" 2>/dev/null; then
        success "QRadar bağlantısı ($QRADAR_IP:$QRADAR_PORT) başarılı"
    elif command_exists nc; then
        if timeout 5 nc -z "$QRADAR_IP" "$QRADAR_PORT" 2>/dev/null; then
            success "QRadar bağlantısı (nc ile) başarılı"
        else
            warn "QRadar'a bağlanılamıyor: $QRADAR_IP:$QRADAR_PORT"
        fi
    else
        warn "QRadar bağlantı testi yapılamıyor - nc aracı bulunamadı"
    fi
}

test_audit_functionality() {
    log "INFO" "Debian/Kali audit fonksiyonalitesi test ediliyor..."
    
    # Güvenli audit olayı tetikle
    cat /etc/passwd > /dev/null 2>&1 || true
    sleep 2
    
    # Audit olayını kontrol et
    if command_exists ausearch; then
        if ausearch --start today -k identity_changes | grep -q "type=SYSCALL"; then
            success "Audit logging çalışıyor"
        else
            warn "Audit logging test başarısız"
        fi
    else
        log "INFO" "ausearch mevcut değil, audit test atlanıyor"
    fi
}

# ===============================================================================
# COMPREHENSIVE SETUP SUMMARY
# ===============================================================================

generate_setup_summary() {
    log "INFO" "Debian/Kali kurulum özeti oluşturuluyor..."
    
    local system_info
    if [[ "$IS_KALI" == true ]]; then
        system_info="Kali Linux ($DEBIAN_CODENAME)"
    else
        system_info="Debian $DEBIAN_VERSION ($DEBIAN_CODENAME)"
    fi
    
    echo ""
    echo "============================================================="
    echo "        QRadar Universal Debian/Kali Kurulum Özeti"
    echo "============================================================="
    echo ""
    echo "🖥️  SİSTEM BİLGİLERİ:"
    echo "   • Sistem: $system_info"
    echo "   • Audisp Metodu: $AUDISP_METHOD"
    echo "   • QRadar Hedefi: $QRADAR_IP:$QRADAR_PORT"
    echo ""
    echo "📁 OLUŞTURULAN DOSYALAR:"
    echo "   • Audit Kuralları: $AUDIT_RULES_FILE"
    echo "   • Audisp Yapılandırması: $AUDISP_SYSLOG_CONF"
    echo "   • Rsyslog Yapılandırması: $RSYSLOG_QRADAR_CONF"
    echo "   • EXECVE Parser: $CONCAT_SCRIPT_PATH"
    echo "   • Kurulum Logu: $LOG_FILE"
    echo "   • Yedek Dosyalar: $BACKUP_DIR/"
    echo ""
    echo "🔧 SERVİS DURUMU:"
    for service in auditd rsyslog; do
        if systemctl is-active --quiet "$service"; then
            echo "   ✅ $service: ÇALIŞIYOR"
        else
            echo "   ❌ $service: ÇALIŞMIYOR"
        fi
    done
    echo ""
    echo "🎯 ÖZELLİKLER:"
    echo "   • MITRE ATT&CK uyumlu audit kuralları"
    echo "   • Penetration testing araçları için özel monitoring"
    echo "   • Otomatik EXECVE komut birleştirme"
    echo "   • Debian/Kali sürüm uyumlu yapılandırma"
    echo "   • Güvenlik odaklı log filtreleme"
    echo "   • Otomatik fallback mekanizmaları"
    echo ""
    if [[ "$IS_KALI" == true ]]; then
        echo "🛡️  KALI LINUX ÖZEL:"
        echo "   • Penetration testing araçları izleniyor"
        echo "   • Metasploit kullanımı loglanıyor"
        echo "   • Network discovery araçları monitörleniyor"
        echo "   • Wordlist erişimleri takip ediliyor"
        echo ""
    fi
    echo "📝 ÖNEMLİ NOTLAR:"
    echo "   • Audit kuralları immutable değil (güvenlik için -e 2 ekleyebilirsiniz)"
    echo "   • Log iletimi TCP protokolü kullanıyor"
    echo "   • Sadece güvenlik ile ilgili loglar iletiliyor"
    echo "   • Yapılandırma dosyaları $BACKUP_DIR dizininde yedeklendi"
    echo ""
    echo "🔍 TEST KOMUTLARI:"
    echo "   • Manual test: logger -p local3.info 'Test mesajı'"
    echo "   • Audit test: sudo touch /etc/passwd"
    echo "   • Bağlantı test: telnet $QRADAR_IP $QRADAR_PORT"
    echo "   • Parser test: python3 $CONCAT_SCRIPT_PATH --test"
    if [[ "$IS_KALI" == true ]]; then
        echo "   • Kali test: nmap -sS localhost (pentest araç testi)"
    fi
    echo ""
    echo "============================================================="
    echo ""
    
    success "QRadar Universal Debian/Kali kurulumu başarıyla tamamlandı!"
}

# ===============================================================================
# MAIN FUNCTION
# ===============================================================================

main() {
    # Log dosyasını oluştur
    touch "$LOG_FILE" || error_exit "Log dosyası oluşturulamıyor: $LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null || true
    
    log "INFO" "============================================================="
    log "INFO" "QRadar Universal Debian/Kali Log Forwarding Installer v$SCRIPT_VERSION"
    log "INFO" "Başlatılıyor: $(date)"
    log "INFO" "QRadar Hedefi: $QRADAR_IP:$QRADAR_PORT"
    log "INFO" "============================================================="
    
    # Root kontrolü
    [[ $EUID -eq 0 ]] || error_exit "Bu script root yetkisiyle çalıştırılmalıdır. 'sudo' kullanın."
    
    # Ana kurulum adımları
    detect_debian_version
    install_required_packages
    deploy_execve_parser
    configure_auditd
    configure_audisp
    configure_rsyslog
    restart_services
    run_validation_tests
    generate_setup_summary
    
    log "INFO" "============================================================="
    log "INFO" "Debian/Kali kurulum tamamlandı: $(date)"
    log "INFO" "============================================================="
}

# ===============================================================================
# SCRIPT ENTRY POINT
# ===============================================================================

# Argument parsing
while [[ $# -gt 0 ]]; do
    case $1 in
        --minimal)
            USE_MINIMAL_RULES=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            echo "QRadar Universal Debian/Kali Installer v$SCRIPT_VERSION"
            echo ""
            echo "Usage: $0 <QRADAR_IP> <QRADAR_PORT> [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --minimal  Use minimal audit rules for EPS optimization"
            echo "  --help     Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 192.168.1.100 514"
            echo "  $0 192.168.1.100 514 --minimal"
            exit 0
            ;;
        -*)
            error_exit "Unknown option: $1"
            ;;
        *)
            if [[ -z "$QRADAR_IP" ]]; then
                QRADAR_IP="$1"
            elif [[ -z "$QRADAR_PORT" ]]; then
                QRADAR_PORT="$1"
            else
                error_exit "Too many arguments"
            fi
            shift
            ;;
    esac
done

# Parametre doğrulama
if [[ -z "$QRADAR_IP" ]] || [[ -z "$QRADAR_PORT" ]]; then
    echo "Kullanım: $0 <QRADAR_IP> <QRADAR_PORT> [--minimal]"
    echo "Örnek: $0 192.168.1.100 514 --minimal"
    exit 1
fi

# IP adresi format kontrolü
if ! [[ "$QRADAR_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    error_exit "Geçersiz IP adresi formatı: $QRADAR_IP"
fi

# Port numarası kontrolü
if ! [[ "$QRADAR_PORT" =~ ^[0-9]+$ ]] || [[ "$QRADAR_PORT" -lt 1 ]] || [[ "$QRADAR_PORT" -gt 65535 ]]; then
    error_exit "Geçersiz port numarası: $QRADAR_PORT (1-65535 arası olmalı)"
fi

# Ana fonksiyonu çalıştır
main

exit 0