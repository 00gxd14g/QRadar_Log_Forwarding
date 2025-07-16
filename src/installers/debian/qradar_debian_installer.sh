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

set -euo pipefail

# ===============================================================================
# GLOBAL DEĞIŞKENLER
# ===============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="4.0.0-debian-universal"
readonly LOG_FILE="/var/log/qradar_debian_setup.log"
readonly BACKUP_DIR="/etc/qradar_backup_$(date +%Y%m%d_%H%M%S)"

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
        local backup_file="$BACKUP_DIR/$(basename "$file").$(date +%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$backup_file" || warn "$file yedeklenemedi"
        log "INFO" "$file dosyası $backup_file konumuna yedeklendi"
    fi
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

# MITRE ATT&CK teknik eşlemeleri (Debian/Kali özel)
MITRE_TECHNIQUES = {
    'T1003': ['cat /etc/shadow', 'cat /etc/gshadow', 'getent shadow', 'john', 'hashcat'],
    'T1059': ['bash', 'sh', 'zsh', 'python', 'perl', 'ruby', 'php', 'node', 'msfconsole'],
    'T1070': ['history -c', 'rm /root/.bash_history', 'shred', 'wipe', 'bleachbit'],
    'T1071': ['curl', 'wget', 'ftp', 'sftp', 'nc', 'netcat'],
    'T1082': ['uname -a', 'lscpu', 'lshw', 'dmidecode', 'systeminfo'],
    'T1087': ['who', 'w', 'last', 'lastlog', 'id', 'getent passwd'],
    'T1105': ['scp', 'rsync', 'socat', 'ncat', 'meterpreter'],
    'T1548': ['sudo', 'su -', 'pkexec', 'gksudo'],
    'T1562': ['systemctl stop auditd', 'service auditd stop', 'auditctl -e 0'],
    'T1033': ['whoami', 'id', 'logname'],
    'T1018': ['nmap', 'netdiscover', 'arp-scan', 'fping'],
    'T1046': ['nmap', 'masscan', 'zmap', 'rustscan'],
    'T1083': ['find', 'locate', 'ls -la', 'dir'],
}

class DebianExecveParser:
    def __init__(self):
        # Signal handler'ları ayarla
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        self.system_type = self._detect_system()
    
    def _detect_system(self):
        """Sistem tipini tespit et (Debian/Kali)"""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if 'kali' in content.lower():
                    return "Kali"
                elif 'debian' in content.lower():
                    return "Debian"
                else:
                    return "Unknown"
        except:
            return "Unknown"
    
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
            
            # MITRE tekniklerini analiz et
            mitre_techniques = self._analyze_mitre_techniques(combined_command)
            mitre_info = ""
            if mitre_techniques:
                mitre_info = f' mitre_techniques="{",".join(mitre_techniques)}"'
            
            # Sistem tipini ekle
            system_info = f' system_type="{self.system_type}"'
            
            # Birleştirilmiş komutu tek alan olarak ekle
            processed_line = f"DEBIAN_PROCESSED: {cleaned_line} cmd=\"{combined_command}\"{mitre_info}{system_info}"
            return processed_line
            
        except Exception as e:
            # Hata durumunda orijinal satırı döndür
            return line
    
    def _analyze_mitre_techniques(self, command):
        """Komutta MITRE ATT&CK tekniklerini tespit et"""
        found_techniques = []
        command_lower = command.lower()
        
        for technique, patterns in MITRE_TECHNIQUES.items():
            for pattern in patterns:
                if pattern.lower() in command_lower:
                    found_techniques.append(technique)
                    break
        return list(set(found_techniques))
    
    def send_to_qradar(self, message, qradar_ip, qradar_port):
        """İşlenmiş mesajı QRadar'a TCP ile gönder"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((qradar_ip, int(qradar_port)))
            sock.send((message + "\n").encode('utf-8'))
            sock.close()
            return True
        except Exception:
            return False
    
    def run(self):
        """Ana işlem döngüsü"""
        # Test modu kontrolü
        if len(sys.argv) > 1 and sys.argv[1] == "--test":
            test_line = 'audit(1234567890.123:456): type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="nmap" a1="-sS" a2="192.168.1.0/24"'
            result = self.process_execve_line(test_line)
            if result and "DEBIAN_PROCESSED" in result and "T1046" in result:
                print(f"{self.system_type} EXECVE parser test başarılı")
                return True
            else:
                print(f"{self.system_type} EXECVE parser test başarısız")
                return False
        
        # QRadar bağlantı bilgilerini al
        qradar_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
        qradar_port = sys.argv[2] if len(sys.argv) > 2 else "514"
        
        try:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    processed_line = self.process_execve_line(line)
                    if processed_line is not None:
                        # QRadar'a göndermeyi dene, başarısız olursa stdout'a yaz
                        if not self.send_to_qradar(processed_line, qradar_ip, qradar_port):
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
# QRadar Universal Debian/Kali Audit Rules v4.0.0
# Debian 9+ ve tüm Kali sürümleri için uyumlu
# MITRE ATT&CK Framework uyumlu güvenlik monitoring

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
    
    local system_name
    if [[ "$IS_KALI" == true ]]; then
        system_name="Kali Linux"
    else
        system_name="Debian $DEBIAN_VERSION ($DEBIAN_CODENAME)"
    fi
    
    cat > "$RSYSLOG_QRADAR_CONF" << EOF
# QRadar Universal Debian/Kali Log Forwarding Configuration v4.0.0
# $system_name için optimize edilmiş
# Üretim ortamı hazır yapılandırma

# Gerekli modülleri yükle
module(load="omprog")
module(load="imfile")

# Ana kuyruk yapılandırması (yüksek performans için)
main_queue(
    queue.type="linkedlist"
    queue.filename="qradar_debian_queue"
    queue.maxdiskspace="2g"
    queue.size="100000"
    queue.dequeuebatchsize="1000"
    queue.saveonshutdown="on"
    queue.timeoutshutdown="10000"
)

# LEEF v2 template for QRadar integration
template(name="LEEFv2Debian" type="string" 
         string="LEEF:2.0|Linux|Debian|4.0.0|%\$.audit_type%|^|devTime=%timereported:::date-rfc3339%^src=%hostname%^auid=%\$.auid%^uid=%\$.uid%^euid=%\$.euid%^pid=%\$.pid%^exe=%\$.exe%^cmd=%\$.full_command%^success=%\$.success%^key=%\$.key%^system_type=Debian^version=$DEBIAN_VERSION\\n")

# QRadar için template
template(name="QRadarDebianFormat" type="string" 
         string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name%: %msg%\\n")

# Enhanced noise reduction - Block unnecessary daemon and kernel messages
if (\$msg contains "systemd:" and not (\$msg contains "Failed" or \$msg contains "failed" or \$msg contains "error" or \$msg contains "denied")) or 
   \$msg contains "NetworkManager" or 
   \$msg contains "dhclient" or 
   \$msg contains "chronyd" or 
   \$msg contains "avahi" or
   \$msg contains "dbus" or
   \$msg contains "cron[" or
   \$msg contains "CRON[" or
   \$msg contains "anacron" or
   \$msg contains "logrotate" or
   \$msg contains "rsyslog:" or
   \$msg contains "systemd-logind" or
   \$msg contains "systemd-resolved" or
   \$msg contains "systemd-timesyncd" then {
    stop
}

# Enhanced kernel message filtering - Only security relevant events  
if \$syslogfacility-text == "kern" and not (\$msg contains "denied" or \$msg contains "blocked" or \$msg contains "failed" or \$msg contains "segfault" or \$msg contains "killed" or \$msg contains "audit" or \$msg contains "firewall") then {
    stop
}

# Debian/Kali syslog dosyasını izle (kritik olaylar için)
input(
    type="imfile"
    file="/var/log/syslog"
    tag="debian-syslog"
    facility="local4"
    ruleset="debian_syslog_processing"
)

# Debian/Kali syslog işleme kuralları - Enhanced MITRE ATT&CK monitoring
ruleset(name="debian_syslog_processing") {
    # Enhanced security event detection including Kali-specific tools
    if \$msg contains "FAILED" or \$msg contains "denied" or \$msg contains "authentication" or \$msg contains "sudo" or \$msg contains "su:" or
       \$msg contains "Invalid user" or \$msg contains "Failed password" or \$msg contains "Connection closed" or
       \$msg contains "Accepted publickey" or \$msg contains "Accepted password" or \$msg contains "session opened" or 
       \$msg contains "session closed" or \$msg contains "privilege escalation" or \$msg contains "pkexec" or
       \$msg contains "polkit" or \$msg contains "pam_" or \$msg contains "login:" or \$msg contains "logout:" or
       \$msg contains "useradd" or \$msg contains "userdel" or \$msg contains "usermod" or \$msg contains "groupadd" or
       \$msg contains "passwd:" or \$msg contains "chage" or \$msg contains "mount" or \$msg contains "umount" or
       \$msg contains "iptables" or \$msg contains "firewall" or \$msg contains "ufw" or 
       \$msg contains "service started" or \$msg contains "service stopped" or \$msg contains "systemctl" or
       \$msg contains "crontab" or \$msg contains "at[" or \$msg contains "batch" or
       \$msg contains "nmap" or \$msg contains "metasploit" or \$msg contains "aircrack" or \$msg contains "hydra" or
       \$msg contains "sqlmap" or \$msg contains "nikto" or \$msg contains "gobuster" or \$msg contains "dirb" then {
        # LEEF v2 format for enhanced events
        action(
            type="omfwd"
            target="$QRADAR_IP"
            port="$QRADAR_PORT"
            protocol="tcp"
            template="LEEFv2Debian"
            queue.type="linkedlist"
            queue.size="50000"
            action.resumeRetryCount="-1"
            action.reportSuspension="on"
        )
        
        # Traditional format for compatibility
        action(
            type="omfwd"
            target="$QRADAR_IP"
            port="$QRADAR_PORT"
            protocol="tcp"
            template="QRadarDebianFormat"
            queue.type="linkedlist"
            queue.size="50000"
            action.resumeRetryCount="-1"
            action.reportSuspension="on"
        )
    }
    stop
}

# MITRE ATT&CK File Activity Monitoring for Debian/Kali
input(
    type="imfile"
    file="/var/log/dpkg.log"
    tag="debian-package"
    facility="local5"
    ruleset="debian_file_activity_processing"
)

ruleset(name="debian_file_activity_processing") {
    # Package installation/removal monitoring (T1505.003, T1027) + Kali tool installations
    if \$msg contains "install" or \$msg contains "remove" or \$msg contains "purge" or \$msg contains "configure" then {
        # LEEF v2 format for package activities
        action(
            type="omfwd"
            target="$QRADAR_IP"
            port="$QRADAR_PORT"
            protocol="tcp"
            template="LEEFv2Debian"
            queue.type="linkedlist"
            queue.size="25000"
            action.resumeRetryCount="-1"
        )
        
        # Traditional format
        action(
            type="omfwd"
            target="$QRADAR_IP"
            port="$QRADAR_PORT"
            protocol="tcp"
            template="QRadarDebianFormat"
            queue.type="linkedlist"
            queue.size="25000"
            action.resumeRetryCount="-1"
        )
    }
    stop
}

# Audit log'larını işle (local3 facility) with LEEF v2 support
if \$syslogfacility-text == "local3" then {
    # Gürültülü audit mesajlarını filtrele
    if \$msg contains "proctitle=" or \$msg contains "PROCTITLE" or \$msg contains "unknown file" then {
        stop
    }
    
    # Extract audit fields for LEEF processing
    set \$.audit_type = regex_extract(\$msg, "type=([A-Z_]+)", 0, 1, "UNKNOWN");
    set \$.auid = regex_extract(\$msg, "auid=([0-9-]+)", 0, 1, "-1");
    set \$.uid = regex_extract(\$msg, "uid=([0-9]+)", 0, 1, "-1");
    set \$.euid = regex_extract(\$msg, "euid=([0-9]+)", 0, 1, "-1");
    set \$.pid = regex_extract(\$msg, "pid=([0-9]+)", 0, 1, "-1");
    set \$.exe = regex_extract(\$msg, "exe=\\"([^\\"]+)\\"", 0, 1, "unknown");
    set \$.success = regex_extract(\$msg, "success=([a-z]+)", 0, 1, "unknown");
    set \$.key = regex_extract(\$msg, "key=\\"([^\\"]+)\\"", 0, 1, "none");
    
    # Enhanced EXECVE command processing 
    if \$msg contains "type=EXECVE" then {
        # Enhanced EXECVE command reconstruction with extended argument support
        set \$.a0 = regex_extract(\$msg, "a0=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a1 = regex_extract(\$msg, "a1=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a2 = regex_extract(\$msg, "a2=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a3 = regex_extract(\$msg, "a3=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a4 = regex_extract(\$msg, "a4=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a5 = regex_extract(\$msg, "a5=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a6 = regex_extract(\$msg, "a6=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a7 = regex_extract(\$msg, "a7=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a8 = regex_extract(\$msg, "a8=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a9 = regex_extract(\$msg, "a9=\\"([^\\"]+)\\"", 0, 1, "");
        
        # Build complete command line with all arguments
        set \$.full_command = \$.a0;
        if \$.a1 != "" then set \$.full_command = \$.full_command & " " & \$.a1;
        if \$.a2 != "" then set \$.full_command = \$.full_command & " " & \$.a2;
        if \$.a3 != "" then set \$.full_command = \$.full_command & " " & \$.a3;
        if \$.a4 != "" then set \$.full_command = \$.full_command & " " & \$.a4;
        if \$.a5 != "" then set \$.full_command = \$.full_command & " " & \$.a5;
        if \$.a6 != "" then set \$.full_command = \$.full_command & " " & \$.a6;
        if \$.a7 != "" then set \$.full_command = \$.full_command & " " & \$.a7;
        if \$.a8 != "" then set \$.full_command = \$.full_command & " " & \$.a8;
        if \$.a9 != "" then set \$.full_command = \$.full_command & " " & \$.a9;
        
        # Send with traditional parser
        action(
            type="omprog"
            binary="$CONCAT_SCRIPT_PATH $QRADAR_IP $QRADAR_PORT"
            template="RSYSLOG_TraditionalFileFormat"
            queue.type="linkedlist"
            queue.size="10000"
            action.resumeRetryCount="-1"
        )
        
        # Send LEEF v2 format directly to QRadar
        action(
            type="omfwd"
            target="$QRADAR_IP"
            port="$QRADAR_PORT"
            protocol="tcp"
            template="LEEFv2Debian"
            queue.type="linkedlist"
            queue.size="25000"
            action.resumeRetryCount="-1"
            action.reportSuspension="on"
        )
        stop
    } else {
        set \$.full_command = "N/A";
    }
    
    # Diğer audit mesajlarını dual format ile ilet (LEEF v2 + Traditional)
    # LEEF v2 format
    action(
        type="omfwd"
        target="$QRADAR_IP"
        port="$QRADAR_PORT"
        protocol="tcp"
        template="LEEFv2Debian"
        queue.type="linkedlist"
        queue.size="50000"
        queue.dequeuebatchsize="500"
        action.resumeRetryCount="-1"
        action.reportSuspension="on"
        action.reportSuspensionContinuation="on"
        action.resumeInterval="10"
    )
    
    # Traditional format
    action(
        type="omfwd"
        target="$QRADAR_IP"
        port="$QRADAR_PORT"
        protocol="tcp"
        template="QRadarDebianFormat"
        queue.type="linkedlist"
        queue.size="50000"
        queue.dequeuebatchsize="500"
        action.resumeRetryCount="-1"
        action.reportSuspension="on"
        action.reportSuspensionContinuation="on"
        action.resumeInterval="10"
    )
    
    stop
}

# Kimlik doğrulama olayları (authpriv/auth) - Dual Format
if \$syslogfacility-text == "authpriv" or \$syslogfacility-text == "auth" then {
    # Sadece güvenlik ile ilgili auth olaylarını dual format ile ilet
    if \$msg contains "sudo" or \$msg contains "su:" or \$msg contains "ssh" or \$msg contains "login" or \$msg contains "authentication" or \$msg contains "FAILED" or \$msg contains "invalid" or \$msg contains "denied" then {
        # LEEF v2 format for auth events
        action(
            type="omfwd"
            target="$QRADAR_IP"
            port="$QRADAR_PORT"
            protocol="tcp"
            template="LEEFv2Debian"
            queue.type="linkedlist"
            queue.size="25000"
            action.resumeRetryCount="-1"
        )
        
        # Traditional format for auth events
        action(
            type="omfwd"
            target="$QRADAR_IP"
            port="$QRADAR_PORT"
            protocol="tcp"
            template="QRadarDebianFormat"
            queue.type="linkedlist"
            queue.size="25000"
            action.resumeRetryCount="-1"
        )
    }
    stop
}

# Kritik sistem mesajları (önem seviyesi 3 ve altı) - Dual Format
if \$syslogseverity <= 3 then {
    # Sistem gürültüsünü filtrele
    if not (\$msg contains "systemd:" or \$msg contains "NetworkManager" or \$msg contains "chronyd") then {
        # LEEF v2 format for critical messages
        action(
            type="omfwd"
            target="$QRADAR_IP"
            port="$QRADAR_PORT"
            protocol="tcp"
            template="LEEFv2Debian"
            queue.type="linkedlist"
            queue.size="25000"
            action.resumeRetryCount="-1"
        )
        
        # Traditional format for critical messages
        action(
            type="omfwd"
            target="$QRADAR_IP"
            port="$QRADAR_PORT"
            protocol="tcp"
            template="QRadarDebianFormat"
            queue.type="linkedlist"
            queue.size="25000"
            action.resumeRetryCount="-1"
        )
    }
}

# =================================================================
# FALLBACK: Doğrudan audit.log dosyası izleme
# =================================================================

input(
    type="imfile"
    file="/var/log/audit/audit.log"
    tag="audit-direct"
    facility="local3"
    ruleset="direct_audit_processing"
)

ruleset(name="direct_audit_processing") {
    # Extract audit fields for LEEF processing
    set \$.audit_type = regex_extract(\$msg, "type=([A-Z_]+)", 0, 1, "UNKNOWN");
    set \$.auid = regex_extract(\$msg, "auid=([0-9-]+)", 0, 1, "-1");
    set \$.uid = regex_extract(\$msg, "uid=([0-9]+)", 0, 1, "-1");
    set \$.euid = regex_extract(\$msg, "euid=([0-9]+)", 0, 1, "-1");
    set \$.pid = regex_extract(\$msg, "pid=([0-9]+)", 0, 1, "-1");
    set \$.exe = regex_extract(\$msg, "exe=\\"([^\\"]+)\\"", 0, 1, "unknown");
    set \$.success = regex_extract(\$msg, "success=([a-z]+)", 0, 1, "unknown");
    set \$.key = regex_extract(\$msg, "key=\\"([^\\"]+)\\"", 0, 1, "none");
    
    # Enhanced EXECVE processing in fallback mode
    if \$msg contains "type=EXECVE" then {
        # Enhanced EXECVE command reconstruction with extended arguments
        set \$.a0 = regex_extract(\$msg, "a0=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a1 = regex_extract(\$msg, "a1=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a2 = regex_extract(\$msg, "a2=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a3 = regex_extract(\$msg, "a3=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a4 = regex_extract(\$msg, "a4=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a5 = regex_extract(\$msg, "a5=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a6 = regex_extract(\$msg, "a6=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a7 = regex_extract(\$msg, "a7=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a8 = regex_extract(\$msg, "a8=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a9 = regex_extract(\$msg, "a9=\\"([^\\"]+)\\"", 0, 1, "");
        
        # Build complete command line with all arguments
        set \$.full_command = \$.a0;
        if \$.a1 != "" then set \$.full_command = \$.full_command & " " & \$.a1;
        if \$.a2 != "" then set \$.full_command = \$.full_command & " " & \$.a2;
        if \$.a3 != "" then set \$.full_command = \$.full_command & " " & \$.a3;
        if \$.a4 != "" then set \$.full_command = \$.full_command & " " & \$.a4;
        if \$.a5 != "" then set \$.full_command = \$.full_command & " " & \$.a5;
        if \$.a6 != "" then set \$.full_command = \$.full_command & " " & \$.a6;
        if \$.a7 != "" then set \$.full_command = \$.full_command & " " & \$.a7;
        if \$.a8 != "" then set \$.full_command = \$.full_command & " " & \$.a8;
        if \$.a9 != "" then set \$.full_command = \$.full_command & " " & \$.a9;
        
        # Send with traditional parser
        action(
            type="omprog"
            binary="$CONCAT_SCRIPT_PATH $QRADAR_IP $QRADAR_PORT"
            template="RSYSLOG_TraditionalFileFormat"
        )
        
        # Send LEEF v2 format directly
        action(
            type="omfwd"
            target="$QRADAR_IP"
            port="$QRADAR_PORT"
            protocol="tcp"
            template="LEEFv2Debian"
            queue.type="linkedlist"
            queue.size="25000"
            action.resumeRetryCount="-1"
        )
        
        # Send traditional format directly
        action(
            type="omfwd"
            target="$QRADAR_IP"
            port="$QRADAR_PORT"
            protocol="tcp"
            template="QRadarDebianFormat"
            queue.type="linkedlist"
            queue.size="25000"
            action.resumeRetryCount="-1"
        )
        stop
    } else {
        set \$.full_command = "N/A";
    }
    
    # Diğer audit olaylarını dual format ile ilet (LEEF v2 + Traditional)
    # LEEF v2 format
    action(
        type="omfwd"
        target="$QRADAR_IP"
        port="$QRADAR_PORT"
        protocol="tcp"
        template="LEEFv2Debian"
        queue.type="linkedlist"
        queue.size="25000"
        action.resumeRetryCount="-1"
        action.reportSuspension="on"
    )
    
    # Traditional format
    action(
        type="omfwd"
        target="$QRADAR_IP"
        port="$QRADAR_PORT"
        protocol="tcp"
        template="QRadarDebianFormat"
        queue.type="linkedlist"
        queue.size="25000"
        action.resumeRetryCount="-1"
        action.reportSuspension="on"
    )
    
    stop
}
EOF
    
    chmod 644 "$RSYSLOG_QRADAR_CONF"
    success "Rsyslog Debian/Kali Universal yapılandırması tamamlandı"
}

# ===============================================================================
# SERVICE MANAGEMENT
# ===============================================================================

restart_services() {
    log "INFO" "Debian/Kali servisleri yeniden başlatılıyor..."
    
    # Servisleri enable et
    safe_execute "auditd servisini enable etme" systemctl enable auditd
    safe_execute "rsyslog servisini enable etme" systemctl enable rsyslog
    
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
    local test_message="QRadar Debian/Kali Universal Installer test $(date '+%Y%m%d%H%M%S')"
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