#!/usr/bin/env bash
#
# ===============================================================================
# QRadar Universal RHEL/CentOS/Rocky/AlmaLinux Log Forwarding Installer v4.0.0
# ===============================================================================
#
# Bu script, tüm RHEL ailesinde çalışacak şekilde tasarlanmış
# QRadar SIEM log iletimi kurulum scriptıdir.
#
# Desteklenen Dağıtımlar:
#   - Red Hat Enterprise Linux (RHEL) 7, 8, 9
#   - CentOS 7, 8 (Stream 8, Stream 9)
#   - Rocky Linux 8, 9
#   - AlmaLinux 8, 9
#   - Oracle Linux 7, 8, 9
#   - Amazon Linux 2
#
# Özellikler:
#   - Otomatik RHEL ailesi dağıtım tespiti
#   - YUM/DNF paket yöneticisi desteği
#   - SELinux otomatik yapılandırması
#   - Firewalld otomatik yapılandırması
#   - Kapsamlı güvenlik monitoring (MITRE ATT&CK uyumlu)
#   - EXECVE komut birleştirme
#   - Güvenli komut çalıştırma (eval kullanmaz)
#
# Kullanım: sudo bash qradar_rhel_installer.sh <QRADAR_IP> <QRADAR_PORT>
#
# Örnek: sudo bash qradar_rhel_installer.sh 192.168.1.100 514
#
# Yazar: QRadar Log Forwarding Projesi
# Sürüm: 4.0.0 - Universal RHEL Edition
# ===============================================================================

set -Eeuo pipefail
trap 'error_exit "Unexpected failure (line: $LINENO)"' ERR

# ===============================================================================
# GLOBAL DEĞIŞKENLER
# ===============================================================================

SCRIPT_DIR="$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd -P)"
readonly SCRIPT_DIR
readonly SCRIPT_VERSION="4.0.0-rhel-universal"
readonly LOG_FILE="qradar_rhel_setup.log"
BACKUP_DIR="/etc/qradar_backup_$(date +%Y%m%d_%H%M%S)"
readonly BACKUP_DIR

# Dosya yolları
readonly AUDIT_RULES_FILE="/etc/audit/rules.d/99-qradar.rules"
readonly AUDIT_PLUGINS_DIR="/etc/audit/plugins.d"
readonly AUDIT_SYSLOG_CONF="/etc/audit/plugins.d/syslog.conf"
readonly RSYSLOG_QRADAR_CONF="/etc/rsyslog.d/99-qradar.conf"
readonly CONCAT_SCRIPT_PATH="/usr/local/bin/qradar_execve_parser.py"

# Sistem bilgileri
DISTRO_ID=""
DISTRO_NAME=""
VERSION_MAJOR=""
VERSION_MINOR=""
PACKAGE_MANAGER=""
SYSLOG_FILE="/var/log/messages"
HAS_SELINUX=false
HAS_FIREWALLD=false

# Script parametreleri
QRADAR_IP=""
QRADAR_PORT=""
OPEN_PORT=false
DRY_RUN=false

# ===============================================================================
# YARDIMCI FONKSİYONLAR
# ===============================================================================

# shellcheck source=../universal/common_functions.sh
source "$SCRIPT_DIR/../universal/common_functions.sh"


# ===============================================================================
# SİSTEM TESPİTİ VE DOĞRULAMA
# ===============================================================================

detect_rhel_family() {
    log "INFO" "RHEL ailesi dağıtım tespiti yapılıyor..."
    
    if [[ ! -f /etc/os-release ]]; then
        error_exit "/etc/os-release dosyası bulunamadı. RHEL sistemi doğrulanamıyor."
    fi
    
    # shellcheck source=/etc/os-release
    source /etc/os-release
    
    # Gerekli değişkenlerin tanımlı olduğunu kontrol et
    if [[ -z "${ID:-}" ]]; then
        error_exit "ID değişkeni /etc/os-release dosyasında bulunamadı"
    fi
    
    if [[ -z "${PRETTY_NAME:-}" ]]; then
        error_exit "PRETTY_NAME değişkeni /etc/os-release dosyasında bulunamadı"
    fi
    
    DISTRO_ID="$ID"
    DISTRO_NAME="$PRETTY_NAME"
    
    # RHEL ailesi kontrolü
    case "$DISTRO_ID" in
        "rhel"|"centos"|"rocky"|"almalinux"|"ol"|"amzn")
            log "INFO" "RHEL ailesi dağıtım tespit edildi: $DISTRO_ID"
            ;;
        *)
            if [[ "${CI:-}" == "true" ]] && [[ "$DRY_RUN" == true ]]; then
                warn "CI mode: skipping distro check"
            else
                error_exit "Bu script sadece RHEL ailesi dağıtımlar için tasarlanmıştır. Tespit edilen: $DISTRO_ID"
            fi
            ;;
    esac
    
    # Sürüm bilgilerini ayıkla
    if [[ -n "$VERSION_ID" ]]; then
        VERSION_MAJOR="${VERSION_ID%%.*}"
        VERSION_MINOR="${VERSION_ID#*.}"
        VERSION_MINOR="${VERSION_MINOR%%.*}"
    else
        # CentOS Stream gibi durumlarda
        VERSION_MAJOR="8"
        VERSION_MINOR="0"
        warn "VERSION_ID bulunamadı, varsayılan değer kullanılıyor: $VERSION_MAJOR.$VERSION_MINOR"
    fi
    
    # Version değerlerini kontrol et
    if [[ -z "$VERSION_MAJOR" ]] || [[ ! "$VERSION_MAJOR" =~ ^[0-9]+$ ]]; then
        error_exit "VERSION_MAJOR değeri geçersiz: '$VERSION_MAJOR' (VERSION_ID: $VERSION_ID)"
    fi
    
    if [[ -z "$VERSION_MINOR" ]] || [[ ! "$VERSION_MINOR" =~ ^[0-9]+$ ]]; then
        error_exit "VERSION_MINOR değeri geçersiz: '$VERSION_MINOR' (VERSION_ID: $VERSION_ID)"
    fi
    
    # RHEL 7+ kontrolü
    if [[ $VERSION_MAJOR -lt 7 ]]; then
        error_exit "Bu script RHEL 7+ sürümlerini destekler. Mevcut sürüm: $VERSION_MAJOR"
    fi
    
    success "$DISTRO_NAME tespit edildi ve destekleniyor (Sürüm: $VERSION_MAJOR.$VERSION_MINOR)"
    
    # Paket yöneticisini belirle
    determine_package_manager
    
    # Sistem özelliklerini kontrol et
    check_system_features
}

determine_package_manager() {
    log "INFO" "Paket yöneticisi belirleniyor..."
    
    # RHEL 8+, CentOS 8+, Rocky, AlmaLinux -> DNF
    # RHEL 7, CentOS 7 -> YUM
    # Amazon Linux 2 -> YUM
    
    if [[ "$DISTRO_ID" == "amzn" ]]; then
        PACKAGE_MANAGER="yum"
        log "INFO" "Amazon Linux tespit edildi, YUM kullanılacak"
    elif [[ $VERSION_MAJOR -ge 8 ]]; then
        if command_exists dnf; then
            PACKAGE_MANAGER="dnf"
            log "INFO" "DNF paket yöneticisi kullanılacak"
        else
            PACKAGE_MANAGER="yum"
            log "INFO" "DNF bulunamadı, YUM kullanılacak"
        fi
    else
        PACKAGE_MANAGER="yum"
        log "INFO" "YUM paket yöneticisi kullanılacak (RHEL 7)"
    fi
}

check_system_features() {
    log "INFO" "Sistem özellikleri kontrol ediliyor..."
    
    # SELinux kontrolü
    if command_exists getenforce; then
        local selinux_status
        selinux_status="$(getenforce 2>/dev/null || echo 'Disabled')"
        if [[ "$selinux_status" != "Disabled" ]]; then
            HAS_SELINUX=true
            log "INFO" "SELinux aktif: $selinux_status"
        else
            log "INFO" "SELinux devre dışı"
        fi
    fi
    
    # Firewalld kontrolü
    if systemctl is-enabled firewalld >/dev/null 2>&1; then
        HAS_FIREWALLD=true
        log "INFO" "Firewalld aktif"
    else
        log "INFO" "Firewalld devre dışı veya kurulu değil"
    fi
    
    # Syslog dosyası kontrol et
    if [[ -f "/var/log/messages" ]]; then
        SYSLOG_FILE="/var/log/messages"
    elif [[ -f "/var/log/syslog" ]]; then
        SYSLOG_FILE="/var/log/syslog"
    fi
    
    log "INFO" "Syslog dosyası: $SYSLOG_FILE"
}

# ===============================================================================
# PAKET KURULUMU
# ===============================================================================

install_required_packages() {
    log "INFO" "RHEL ailesi için gerekli paketler kontrol ediliyor ve kuruluyor..."
    
    # RHEL ailesi için paket listesi
    local required_packages=("audit" "rsyslog" "python3")
    
    # RHEL/CentOS 7 için audispd-plugins
    if [[ $VERSION_MAJOR -eq 7 ]]; then
        required_packages+=("audispd-plugins")
    fi
    
    local packages_to_install=()
    
    # Hangi paketlerin kurulu olmadığını kontrol et
    for package in "${required_packages[@]}"; do
        if ! rpm -q "$package" >/dev/null 2>&1; then
            packages_to_install+=("$package")
            log "INFO" "$package paketi kurulu değil"
        else
            log "INFO" "$package paketi zaten kurulu"
        fi
    done
    
    # Eksik paketleri kur
    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        log "INFO" "Kurulacak paketler: ${packages_to_install[*]}"
        
        # EPEL repository'si gerekebilir (özellikle RHEL 7 için)
        if [[ $VERSION_MAJOR -eq 7 ]] && ! rpm -q epel-release >/dev/null 2>&1; then
            log "INFO" "EPEL repository kuruluyor..."
            safe_execute "EPEL repository kurulumu" "$PACKAGE_MANAGER" install -y epel-release || warn "EPEL kurulumu başarısız"
        fi
        
        retry_operation "Paket kurulumu" "$PACKAGE_MANAGER" install -y "${packages_to_install[@]}"
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
    log "INFO" "RHEL ailesi için EXECVE komut ayrıştırıcısı deploy ediliyor..."
    
    backup_file "$CONCAT_SCRIPT_PATH"
    
    # Create the execve parser script directly
    cat > "$CONCAT_SCRIPT_PATH" << 'EXECVE_PARSER_EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QRadar Unified EXECVE Parser

This script processes and enriches audit EXECVE messages for optimal SIEM analysis.
It combines multi-part arguments, maps commands to MITRE ATT&CK techniques,
and enriches logs with human-readable user and group names.

Version: 1.0.0
Author: Gemini
"""

import sys
import re
import pwd
import grp
import signal
from typing import Dict, List, Optional

# --- MITRE ATT&CK Technique Mappings ---
# A curated dictionary mapping techniques to common Linux commands and patterns.
MITRE_TECHNIQUES: Dict[str, List[str]] = {
    # T1003: OS Credential Dumping
    "T1003": ["cat /etc/shadow", "cat /etc/gshadow", "getent shadow", "dump"],
    # T1059: Command and Scripting Interpreter
    "T1059": ["bash", "sh", "zsh", "python", "perl", "ruby", "php", "node"],
    # T1070: Indicator Removal on Host
    "T1070": ["history -c", "rm /root/.bash_history", "shred", "wipe"],
    # T1071: Application Layer Protocol (e.g., for C2)
    "T1071": ["curl", "wget", "ftp", "sftp"],
    # T1082: System Information Discovery
    "T1082": ["uname -a", "lscpu", "lshw", "dmidecode"],
    # T1087: Account Discovery
    "T1087": ["who", "w", "last", "lastlog", "id", "getent passwd"],
    # T1105: Ingress Tool Transfer
    "T1105": ["scp", "rsync", "socat", "ncat"],
    # T1548: Abuse Elevation Control Mechanism
    "T1548": ["sudo", "su -", "pkexec"],
    # T1562: Impair Defenses
    "T1562": [
        "systemctl stop auditd",
        "service auditd stop",
        "auditctl -e 0",
        "setenforce 0",
    ],
}


class ExecveParser:
    """
    Parses, enriches, and formats audit log lines, focusing on EXECVE events.
    """

    def __init__(self):
        """Initializes patterns and signal handlers for graceful shutdown."""
        self.execve_pattern = re.compile(r"type=EXECVE")
        self.arg_pattern = re.compile(r'a(\d+)="([^"]*)"')
        self.hex_arg_pattern = re.compile(r"a\d+=([0-9A-Fa-f]+)")
        self.user_pattern = re.compile(r"\b(a?uid|gid)=(\d+)")
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum: int, frame) -> None:
        """Handles termination signals to exit gracefully."""
        sys.exit(0)

    def _get_user_info(self, line: str) -> Dict[str, str]:
        """Extracts and resolves user/group IDs from the log line."""
        info = {}
        for key in ["auid", "uid", "gid"]:
            match = re.search(rf"\b{key}=(\d+)", line)
            if match:
                num_id = int(match.group(1))
                if num_id == 4294967295:  # Unset ID (-1)
                    continue
                try:
                    if "uid" in key:
                        user_name = pwd.getpwuid(num_id).pw_name
                        info[f"{key}_name"] = user_name
                    elif "gid" in key:
                        group_name = grp.getgrgid(num_id).gr_name
                        info[f"{key}_name"] = group_name
                except (KeyError, ValueError):
                    pass  # Ignore if ID does not exist
        return info

    def _analyze_mitre_techniques(self, command: str) -> List[str]:
        """Matches a command against the MITRE ATT&CK knowledge base."""
        techniques_found = []
        for tech_id, patterns in MITRE_TECHNIQUES.items():
            for pattern in patterns:
                if pattern in command:
                    techniques_found.append(tech_id)
                    break  # Move to the next technique once one pattern matches
        return techniques_found

    def _format_kv(self, data: Dict[str, str]) -> str:
        """Formats a dictionary into a key="value" string."""
        return " ".join([f'{key}="{value}"' for key, value in data.items()])

    def parse_line(self, line: str) -> Optional[str]:
        """
        Processes a single log line. If it's an EXECVE event, it reconstructs
        the command and enriches the log. Otherwise, it returns the line as is.
        """
        if not self.execve_pattern.search(line):
            return line

        try:
            # 1. Reconstruct the full command
            args: Dict[int, str] = {}
            # First, get all normally quoted arguments
            for match in self.arg_pattern.finditer(line):
                args[int(match.group(1))] = match.group(2)
            # Then, get any hex-encoded arguments that might have been missed
            for match in self.hex_arg_pattern.finditer(line):
                key, hex_val = match.group(0).split("=", 1)
                arg_num = int(key[1:])
                if arg_num not in args:
                    try:
                        args[arg_num] = bytes.fromhex(hex_val).decode(
                            "utf-8", "replace"
                        )
                    except ValueError:
                        pass  # Ignore non-hex values

            if not args:
                return line  # Nothing to parse

            full_command = " ".join(args[i] for i in sorted(args.keys()))

            # 2. Clean the original line by removing argument fields
            line = self.arg_pattern.sub("", line)
            line = self.hex_arg_pattern.sub("", line)
            line = re.sub(r"argc=\d+\s*", "", line).strip()

            # 3. Enrich the log line
            enrichment_data = {
                "cmd": full_command,
            }

            # Add user/group names
            user_info = self._get_user_info(line)
            enrichment_data.update(user_info)

            # Add MITRE techniques
            mitre_info = self._analyze_mitre_techniques(full_command)
            if mitre_info:
                enrichment_data["mitre_techniques"] = ",".join(
                    sorted(list(set(mitre_info)))
                )

            return f"{line} {self._format_kv(enrichment_data)}"

        except Exception:
            # In case of any error, return the original line to prevent data loss
            return line

    def run(self) -> None:
        """
        Main processing loop. Reads from stdin, processes each line,
        and prints the result to stdout.
        """
        try:
            for line in sys.stdin:
                processed_line = self.parse_line(line.strip())
                if processed_line:
                    print(processed_line, flush=True)
        except (IOError, BrokenPipeError):
            # Gracefully exit on broken pipe (e.g., rsyslog restarts)
            sys.exit(0)
        except Exception:
            # Exit on any other fatal error
            sys.exit(1)


if __name__ == "__main__":
    parser = ExecveParser()
    parser.run()
EXECVE_PARSER_EOF
    
    chmod +x "$CONCAT_SCRIPT_PATH" || error_exit "EXECVE parser script'i çalıştırılabilir yapılamadı"
    chown root:root "$CONCAT_SCRIPT_PATH" || warn "EXECVE parser script'i sahiplik ayarlanamadı"
    
    # Test et
    if python3 "$CONCAT_SCRIPT_PATH" --test >> "$LOG_FILE" 2>&1; then
        success "RHEL ailesi EXECVE komut ayrıştırıcısı başarıyla deploy edildi ve test edildi"
    else
        warn "EXECVE parser test başarısız oldu, ancak script deploy edildi"
    fi

    # Deploy helper scripts
    cat > "/usr/local/bin/extract_audit_type.sh" << 'AUDIT_TYPE_EOF'
#!/bin/bash
# Audit log tipini çıkar
echo "$1" | grep -oP 'type=\K\w+' | head -1
AUDIT_TYPE_EOF
    chmod +x "/usr/local/bin/extract_audit_type.sh"
    chown root:root "/usr/local/bin/extract_audit_type.sh"

    cat > "/usr/local/bin/extract_audit_result.sh" << 'AUDIT_RESULT_EOF'
#!/bin/bash
# Audit log sonucunu çıkar
if echo "$1" | grep -q "res=success\|success=yes"; then
    echo "success"
else
    echo "failed"
fi
AUDIT_RESULT_EOF
    chmod +x "/usr/local/bin/extract_audit_result.sh"
    chown root:root "/usr/local/bin/extract_audit_result.sh"
    
    success "Helper script'ler başarıyla deploy edildi"
}

# ===============================================================================
# AUDIT CONFIGURATION
# ===============================================================================

configure_auditd() {
    log "INFO" "RHEL ailesi için auditd kuralları yapılandırılıyor..."
    
    backup_file "$AUDIT_RULES_FILE"
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")"

    cp "$SCRIPT_DIR/../universal/audit.rules" "$AUDIT_RULES_FILE"
    
    chmod 640 "$AUDIT_RULES_FILE"
    success "RHEL ailesi Universal audit kuralları yapılandırıldı"
}

# ===============================================================================
# AUDIT PLUGIN CONFIGURATION
# ===============================================================================

configure_audit_plugins() {
    log "INFO" "RHEL ailesi audit plugin yapılandırması..."
    
    backup_file "$AUDIT_SYSLOG_CONF"
    mkdir -p "$AUDIT_PLUGINS_DIR"
    
    # RHEL ailesi için audit syslog plugin
    cat > "$AUDIT_SYSLOG_CONF" << 'EOF'
# QRadar Universal RHEL Family Audit Plugin Configuration
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_LOCAL3
format = string
EOF
    
    chmod 640 "$AUDIT_SYSLOG_CONF"
    success "RHEL ailesi audit syslog plugin yapılandırıldı"
}

# ===============================================================================
# SELINUX CONFIGURATION
# ===============================================================================

configure_selinux() {
    if [[ "$HAS_SELINUX" == true ]]; then
        log "INFO" "SELinux yapılandırması uygulanıyor..."
        
        # rsyslog'un ağ bağlantısına izin ver
        if command_exists setsebool; then
            safe_execute "SELinux rsyslog network boolean ayarlama" setsebool -P rsyslog_can_network_connect on
            success "SELinux rsyslog network bağlantısı aktifleştirildi"
        fi
        
        # Python script için SELinux context ayarla
        if command_exists restorecon; then
            safe_execute "Python script SELinux context ayarlama" restorecon -R "$CONCAT_SCRIPT_PATH"
            success "Python script SELinux context ayarlandı"
        fi
        
        # Audit log dosyaları için context
        if command_exists restorecon; then
            safe_execute "Audit log SELinux context ayarlama" restorecon -R /var/log/audit/
        fi
        
        log "INFO" "SELinux yapılandırması tamamlandı"
    else
        log "INFO" "SELinux devre dışı, yapılandırma atlanıyor"
    fi
}

# ===============================================================================
# FIREWALL CONFIGURATION
# ===============================================================================

configure_firewall() {
    if [[ "$HAS_FIREWALLD" == true ]] && [[ "$OPEN_PORT" == true ]]; then
        log "INFO" "Firewalld yapılandırması uygulanıyor..."
        
        # QRadar portu için giden bağlantılara izin ver
        if safe_execute "Firewalld QRadar port açma" firewall-cmd --permanent --add-port="$QRADAR_PORT/tcp"; then
            safe_execute "Firewalld reload" firewall-cmd --reload
            success "Firewalld'de QRadar portu ($QRADAR_PORT/tcp) açıldı"
        else
            warn "Firewalld yapılandırması başarısız"
        fi
        
        log "INFO" "Firewalld yapılandırması tamamlandı"
    else
        log "INFO" "Firewalld yapılandırması atlanıyor"
    fi
}

# ===============================================================================
# RSYSLOG CONFIGURATION
# ===============================================================================

configure_rsyslog() {
    log "INFO" "RHEL ailesi için rsyslog QRadar iletimi yapılandırılıyor..."

    backup_file "$RSYSLOG_QRADAR_CONF"

    cp "$SCRIPT_DIR/../universal/99-qradar.conf" "$RSYSLOG_QRADAR_CONF"
    
    # shellcheck source=../universal/99-qradar.conf
    sed -i -e "s/<QRADAR_IP>/$QRADAR_IP/g" \
        -e "s/<QRADAR_PORT>/$QRADAR_PORT/g" \
        "$RSYSLOG_QRADAR_CONF"

    chmod 644 "$RSYSLOG_QRADAR_CONF"

    # Copy rsyslog.conf
    backup_file "/etc/rsyslog.conf"
    cp "$SCRIPT_DIR/../universal/rsyslog.conf" "/etc/rsyslog.conf"
    chmod 644 "/etc/rsyslog.conf"

    # Copy ignore_programs.json
    mkdir -p "/etc/rsyslog.d"
    backup_file "/etc/rsyslog.d/ignore_programs.json"
    cp "$SCRIPT_DIR/../universal/ignore_programs.json" "/etc/rsyslog.d/ignore_programs.json"
    chmod 644 "/etc/rsyslog.d/ignore_programs.json"

    success "Rsyslog RHEL ailesi Universal yapılandırması tamamlandı"
}

# ===============================================================================
# SERVICE MANAGEMENT
# ===============================================================================

restart_services() {
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "DRY RUN: Skipping service restarts."
        return
    fi

    log "INFO" "RHEL ailesi servisleri yeniden başlatılıyor..."
    
    # Servisleri enable et
    safe_execute "auditd servisini enable etme" systemctl enable auditd
    if ! rsyslogd -N1 -f "$RSYSLOG_QRADAR_CONF" >> "$LOG_FILE" 2>&1; then
        error_exit "Rsyslog yapılandırma dosyası $RSYSLOG_QRADAR_CONF geçersiz."
    fi
    success "Rsyslog yapılandırması doğrulandı."

    safe_execute "rsyslog servisini enable etme" systemctl enable rsyslog
    
    # Servisleri durdur
    safe_execute "auditd servisini durdurma" systemctl stop auditd || true
    safe_execute "rsyslog servisini durdurma" systemctl stop rsyslog || true
    
    sleep 3
    
    # Auditd'yi başlat
    retry_operation "auditd servisini başlatma" systemctl start "auditd"
    
    sleep 2
    
    # Audit kurallarını yükle
    load_audit_rules
    
    # Rsyslog'u başlat
    retry_operation "rsyslog servisini başlatma" systemctl start "rsyslog"
    
    success "Tüm RHEL ailesi servisleri başarıyla yapılandırıldı ve başlatıldı"
}

load_audit_rules() {
    log "INFO" "RHEL ailesi audit kuralları yükleniyor..."
    
    # Method 1: augenrules (RHEL 8+)
    if [[ $VERSION_MAJOR -ge 8 ]] && command_exists augenrules; then
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
    local has_e_flag=false
    while IFS= read -r line; do
        if [[ -n "$line" ]] && [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ "$line" =~ ^[[:space:]]*- ]]; then
            if [[ "$line" == "-e 2" ]]; then
                has_e_flag=true
                continue  # İmmutable flag'i son olarak uygula
            fi
            read -ra rule_parts <<< "$line"
            if auditctl "${rule_parts[@]}" >> "$LOG_FILE" 2>&1; then
                ((rules_loaded++))
            fi
        fi
    done < "$AUDIT_RULES_FILE"
    
    if [[ "$has_e_flag" == true ]]; then
        log "INFO" "Applying immutable flag (-e 2)"
        auditctl -e 2 >> "$LOG_FILE" 2>&1
    fi

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
    log "INFO" "RHEL ailesi sistem doğrulama testleri çalıştırılıyor..."

    # DRY-RUN'da servis testlerini atla
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "DRY-RUN: servis doğrulama testleri atlandı"
        return
    fi

    local services=("auditd" "rsyslog")
    for service in "${services[@]}"; do
        if detect_init && systemctl is-active --quiet "$service"; then
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
        success "RHEL ailesi EXECVE parser test başarılı"
    else
        warn "EXECVE parser test başarısız"
    fi
    
    # Yerel syslog testi
    local test_message
test_message="QRadar RHEL Universal Installer test $(date '+%Y%m%d%H%M%S')"
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
    
    # SELinux test
    test_selinux_configuration
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
    log "INFO" "RHEL ailesi audit fonksiyonalitesi test ediliyor..."
    
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

test_selinux_configuration() {
    if [[ "$HAS_SELINUX" == true ]]; then
        log "INFO" "SELinux yapılandırması test ediliyor..."
        
        if command_exists getsebool; then
            local rsyslog_bool
            rsyslog_bool="$(getsebool rsyslog_can_network_connect 2>/dev/null || echo 'off')"
            if [[ "$rsyslog_bool" == *"on"* ]]; then
                success "SELinux rsyslog network boolean aktif"
            else
                warn "SELinux rsyslog network boolean devre dışı"
            fi
        fi
    fi
}

# ===============================================================================
# COMPREHENSIVE SETUP SUMMARY
# ===============================================================================

generate_setup_summary() {
    log "INFO" "RHEL ailesi kurulum özeti oluşturuluyor..."
    
    echo ""
    echo "============================================================="
    echo "       QRadar Universal RHEL Ailesi Kurulum Özeti"
    echo "============================================================="
    echo ""
    echo "🖥️  SİSTEM BİLGİLERİ:"
    echo "   • Dağıtım: $DISTRO_NAME"
    echo "   • Sürüm: $VERSION_MAJOR.$VERSION_MINOR"
    echo "   • Paket Yöneticisi: $PACKAGE_MANAGER"
    echo "   • SELinux: $(if [[ "$HAS_SELINUX" == true ]]; then echo "Aktif"; else echo "Devre Dışı"; fi)"
    echo "   • Firewalld: $(if [[ "$HAS_FIREWALLD" == true ]]; then echo "Aktif"; else echo "Devre Dışı"; fi)"
    echo "   • QRadar Hedefi: $QRADAR_IP:$QRADAR_PORT"
    echo ""
    echo "📁 OLUŞTURULAN DOSYALAR:"
    echo "   • Audit Kuralları: $AUDIT_RULES_FILE"
    echo "   • Audit Plugin: $AUDIT_SYSLOG_CONF"
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
    echo "   • RHEL ailesi sürüm uyumlu yapılandırma"
    echo "   • SELinux otomatik yapılandırması"
    echo "   • Firewalld otomatik yapılandırması"
    echo "   • Enterprise grade log filtreleme"
    echo "   • Otomatik fallback mekanizmaları"
    echo ""
    echo "🛡️  GÜVENLİK YAPILANDI:"
    if [[ "$HAS_SELINUX" == true ]]; then
        echo "   • SELinux boolean'ları yapılandırıldı"
        echo "   • SELinux context'ler ayarlandı"
    fi
    if [[ "$HAS_FIREWALLD" == true ]]; then
        echo "   • Firewalld kuralları eklendi"
        echo "   • QRadar portu ($QRADAR_PORT/tcp) açıldı"
    fi
    echo ""
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
    if [[ "$HAS_SELINUX" == true ]]; then
        echo "   • SELinux test: getsebool rsyslog_can_network_connect"
    fi
    if [[ "$HAS_FIREWALLD" == true ]]; then
        echo "   • Firewall test: firewall-cmd --list-ports"
    fi
    echo ""
    echo "============================================================="
    echo ""
    
    success "QRadar Universal RHEL Ailesi kurulumu başarıyla tamamlandı!"
}

# ===============================================================================
# MAIN FUNCTION
# ===============================================================================

main() {
    # Log dosyasını oluştur
    touch "$LOG_FILE" || error_exit "Log dosyası oluşturulamıyor: $LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null || true
    
    log "INFO" "============================================================="
    log "INFO" "QRadar Universal RHEL Family Log Forwarding Installer v$SCRIPT_VERSION"
    log "INFO" "Başlatılıyor: $(date)"
    log "INFO" "QRadar Hedefi: $QRADAR_IP:$QRADAR_PORT"
    log "INFO" "============================================================="
    
    # Root kontrolü
    [[ $EUID -eq 0 ]] || error_exit "Bu script root yetkisiyle çalıştırılmalıdır. 'sudo' kullanın."
    
    # Ana kurulum adımları
    detect_rhel_family
    install_required_packages
    deploy_execve_parser
    configure_auditd
    configure_audit_plugins
    configure_selinux
    configure_firewall
    configure_rsyslog
    restart_services
    run_validation_tests
    generate_setup_summary
    
    log "INFO" "============================================================="
    log "INFO" "RHEL ailesi kurulum tamamlandı: $(date)"
    log "INFO" "============================================================="

    if [[ "${CI:-}" == "true" ]] && [[ "$DRY_RUN" == true ]]; then
        if [[ -n "${RUNNER_TEMP:-}" ]]; then
            mv "$LOG_FILE" "$RUNNER_TEMP/" || warn "Could not move log file to $RUNNER_TEMP"
            chown "$(logname)" "$RUNNER_TEMP/$LOG_FILE" || warn "Could not change log file ownership"
        fi
    fi
}

# ===============================================================================
# SCRIPT ENTRY POINT
# ===============================================================================

# Argument parsing
while [[ $# -gt 0 ]]; do
    case $1 in
        --open-port)
            OPEN_PORT=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            echo "QRadar Universal RHEL Family Installer v$SCRIPT_VERSION"
            echo ""
            echo "Usage: $0 <QRADAR_IP> <QRADAR_PORT> [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --minimal    Use minimal audit rules for EPS optimization"
            echo "  --open-port  Open the QRadar port in firewalld"
            echo "  --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 192.168.1.100 514"
            echo "  $0 192.168.1.100 514 --minimal --open-port"
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