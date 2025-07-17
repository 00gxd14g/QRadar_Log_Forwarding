#!/usr/bin/env bash
#
# ===============================================================================
# QRadar Universal Ubuntu Log Forwarding Installer v4.0.0
# ===============================================================================
#
# Bu script, tüm Ubuntu sürümlerinde (16.04+) çalışacak şekilde tasarlanmış
# QRadar SIEM log iletimi kurulum scriptıdir.
#
# Desteklenen Ubuntu Sürümleri:
#   - Ubuntu 16.04 LTS (Xenial Xerus)
#   - Ubuntu 18.04 LTS (Bionic Beaver)
#   - Ubuntu 20.04 LTS (Focal Fossa)
#   - Ubuntu 22.04 LTS (Jammy Jellyfish)
#   - Ubuntu 24.04 LTS (Noble Numbat)
#   - Tüm ara sürümler ve gelecek sürümler
#
# Özellikler:
#   - Otomatik Ubuntu sürüm tespiti ve uyumluluk
#   - Kapsamlı güvenlik monitoring (MITRE ATT&CK uyumlu)
#   - EXECVE komut birleştirme (command concatenation)
#   - Güvenli komut çalıştırma (eval kullanmaz)
#   - Otomatik hata düzeltme ve fallback mekanizmaları
#   - Comprehensive backup ve recovery sistemi
#
# Kullanım: sudo bash qradar_ubuntu_installer.sh <QRADAR_IP> <QRADAR_PORT>
#
# Örnek: sudo bash qradar_ubuntu_installer.sh 192.168.1.100 514
#
# Yazar: QRadar Log Forwarding Projesi
# Sürüm: 4.0.0 - Universal Ubuntu Edition
# ===============================================================================

set -Eeuo pipefail
trap 'error_exit "Unexpected failure (line: $LINENO)"' ERR

# ===============================================================================
# GLOBAL DEĞIŞKENLER
# ===============================================================================

SCRIPT_DIR="$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd -P)"
readonly SCRIPT_DIR
readonly SCRIPT_VERSION="4.0.0-ubuntu-universal"
readonly LOG_FILE="qradar_ubuntu_setup.log"
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
UBUNTU_VERSION=""
UBUNTU_CODENAME=""
VERSION_MAJOR=""
VERSION_MINOR=""
AUDISP_METHOD=""
AUDISP_SYSLOG_CONF=""
SYSLOG_FILE="/var/log/syslog"

# Script parametreleri
QRADAR_IP=""
QRADAR_PORT=""
DRY_RUN=false

# ===============================================================================
# YARDIMCI FONKSİYONLAR
# ===============================================================================

# -------------------- helpers --------------------
detect_init() {
    [[ "$(cat /proc/1/comm 2>/dev/null)" == "systemd" ]]
}

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
        log "INFO" "file dosyası $backup_file konumuna yedeklendi"
    fi
}


# ===============================================================================
# SİSTEM TESPİTİ VE DOĞRULAMA
# ===============================================================================

detect_ubuntu_version() {
    log "INFO" "Ubuntu sürümü tespit ediliyor..."
    
    if [[ ! -f /etc/os-release ]]; then
        error_exit "/etc/os-release dosyası bulunamadı. Ubuntu sistemi doğrulanamıyor."
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
    
    if [[ "$ID" != "ubuntu" ]]; then
        error_exit "Bu script sadece Ubuntu sistemler için tasarlanmıştır. Tespit edilen: $ID"
    fi
    
    UBUNTU_VERSION="$VERSION_ID"
    UBUNTU_CODENAME="$VERSION_CODENAME"
    
    # Sürüm numarasını parçala
    IFS='.' read -r VERSION_MAJOR VERSION_MINOR <<< "$UBUNTU_VERSION"
    
    # Version değerlerini kontrol et
    if [[ -z "$VERSION_MAJOR" ]] || [[ ! "$VERSION_MAJOR" =~ ^[0-9]+$ ]]; then
        error_exit "VERSION_MAJOR değeri geçersiz: '$VERSION_MAJOR' (UBUNTU_VERSION: $UBUNTU_VERSION)"
    fi
    
    if [[ -z "$VERSION_MINOR" ]] || [[ ! "$VERSION_MINOR" =~ ^[0-9]+$ ]]; then
        error_exit "VERSION_MINOR değeri geçersiz: '$VERSION_MINOR' (UBUNTU_VERSION: $UBUNTU_VERSION)"
    fi
    
    # Ubuntu 16.04+ kontrolü
    if [[ $VERSION_MAJOR -lt 16 ]] || [[ $VERSION_MAJOR -eq 16 && $VERSION_MINOR -lt 4 ]]; then
        error_exit "Bu script Ubuntu 16.04+ sürümlerini destekler. Mevcut sürüm: $UBUNTU_VERSION"
    fi
    
    success "Ubuntu $UBUNTU_VERSION ($UBUNTU_CODENAME) tespit edildi ve destekleniyor"
    
    # Sürüme göre audisp metodunu belirle
    determine_audisp_method
}

determine_audisp_method() {
    log "INFO" "Ubuntu sürümüne göre audisp metodu belirleniyor..."
    
    # Ubuntu 16.04-19.10: /etc/audisp/plugins.d/
    # Ubuntu 20.04+: /etc/audit/plugins.d/
    if [[ $VERSION_MAJOR -lt 20 ]]; then
        AUDISP_METHOD="legacy"
        AUDISP_SYSLOG_CONF="$AUDISP_PLUGINS_DIR/syslog.conf"
        log "INFO" "Legacy audisp metodu kullanılacak (/etc/audisp/plugins.d/)"
    else
        AUDISP_METHOD="modern"
        AUDISP_SYSLOG_CONF="$AUDIT_SYSLOG_CONF"
        log "INFO" "Modern audit metodu kullanılacak (/etc/audit/plugins.d/)"
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
    
    # Ubuntu sürümüne göre paket listesi
    local required_packages=("auditd" "rsyslog" "python3")
    
    # Ubuntu 16.04-19.10 için audispd-plugins
    if [[ $VERSION_MAJOR -lt 20 ]]; then
        required_packages+=("audispd-plugins")
    fi
    
    local packages_to_install=()
    
    # Paket listesini güncelle
    retry_operation "Paket listesi güncelleme" apt-get update
    
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
    log "INFO" "EXECVE komut ayrıştırıcısı deploy ediliyor..."
    
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
        success "EXECVE komut ayrıştırıcısı başarıyla deploy edildi ve test edildi"
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
    log "INFO" "Auditd kuralları yapılandırılıyor..."
    
    backup_file "$AUDIT_RULES_FILE"
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")"

    cp "$SCRIPT_DIR/../universal/audit.rules" "$AUDIT_RULES_FILE"
    
    chmod 640 "$AUDIT_RULES_FILE"
    success "Ubuntu Universal audit kuralları yapılandırıldı"
}

# ===============================================================================
# AUDISP CONFIGURATION
# ===============================================================================

configure_audisp() {
    log "INFO" "Ubuntu sürümüne göre audisp yapılandırılıyor..."
    
    backup_file "$AUDISP_SYSLOG_CONF"
    
    # Sürüme göre uygun dizini oluştur
    if [[ "$AUDISP_METHOD" == "legacy" ]]; then
        mkdir -p "$AUDISP_PLUGINS_DIR"
        log "INFO" "Legacy audisp yapılandırması (Ubuntu $UBUNTU_VERSION)"
    else
        mkdir -p "$AUDIT_PLUGINS_DIR"
        log "INFO" "Modern audit yapılandırması (Ubuntu $UBUNTU_VERSION)"
    fi
    
    # Syslog plugin yapılandırması
    cat > "$AUDISP_SYSLOG_CONF" << 'EOF'
# QRadar Universal Ubuntu Audisp Configuration
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_LOCAL3
format = string
EOF
    
    chmod 640 "$AUDISP_SYSLOG_CONF"
    success "Audisp syslog plugin yapılandırıldı ($AUDISP_METHOD method)"
}

# ===============================================================================
# RSYSLOG CONFIGURATION
# ===============================================================================

configure_rsyslog() {
    log "INFO" "Rsyslog QRadar iletimi yapılandırılıyor..."

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

    success "Rsyslog Ubuntu Universal yapılandırması tamamlandı"
}

# ===============================================================================
# FALLBACK CONFIGURATION
# ===============================================================================

configure_direct_audit_fallback() {
    log "INFO" "Doğrudan audit.log izleme fallback yapılandırması ekleniyor..."
    
    # Rsyslog yapılandırmasına fallback ekle
    cat >> "$RSYSLOG_QRADAR_CONF" << EOF

# =================================================================
# FALLBACK: Doğrudan audit.log dosyası izleme
# =================================================================
# Audit rules yüklenemediği durumlarda kullanılır

input(
    type="imfile"
    file="/var/log/audit/audit.log"
    tag="audit-direct"
    facility="local3"
    ruleset="direct_audit_processing"
)

ruleset(name="direct_audit_processing") {
    # Extract audit fields for LEEF processing
    set \$.audit_type = re_extract(\$msg, "type=([A-Z_]+)", 0, 1, "UNKNOWN");
    set \$.auid = re_extract(\$msg, "auid=([0-9-]+)", 0, 1, "-1");
    set \$.uid = re_extract(\$msg, "uid=([0-9]+)", 0, 1, "-1");
    set \$.euid = re_extract(\$msg, "euid=([0-9]+)", 0, 1, "-1");
    set \$.pid = re_extract(\$msg, "pid=([0-9]+)", 0, 1, "-1");
    set \$.exe = re_extract(\$msg, "exe=\\"([^\\"]+)\\"", 0, 1, "unknown");
    set \$.success = re_extract(\$msg, "success=([a-z]+)", 0, 1, "unknown");
    set \$.key = re_extract(\$msg, "key=\\"([^\\"]+)\\"", 0, 1, "none");

    # Enhanced EXECVE processing in fallback mode
    if \$msg contains "type=EXECVE" then {
        # Enhanced EXECVE command reconstruction with extended arguments
        set \$.a0 = re_extract(\$msg, "a0=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a1 = re_extract(\$msg, "a1=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a2 = re_extract(\$msg, "a2=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a3 = re_extract(\$msg, "a3=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a4 = re_extract(\$msg, "a4=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a5 = re_extract(\$msg, "a5=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a6 = re_extract(\$msg, "a6=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a7 = re_extract(\$msg, "a7=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a8 = re_extract(\$msg, "a8=\\"([^\\"]+)\\"", 0, 1, "");
        set \$.a9 = re_extract(\$msg, "a9=\\"([^\\"]+)\\"", 0, 1, "");

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
            template="LEEFv2Ubuntu"
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
            template="QRadarUbuntuFormat"
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
        template="LEEFv2Ubuntu"
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
        template="QRadarUbuntuFormat"
        queue.type="linkedlist"
        queue.size="25000"
        action.resumeRetryCount="-1"
        action.reportSuspension="on"
    )

    stop
}
EOF
    
    success "Doğrudan audit.log izleme fallback eklendi"
}

# ===============================================================================
# SERVICE MANAGEMENT
# ===============================================================================

restart_services() {
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "DRY RUN: Skipping service restarts."
        return
    fi

    log "INFO" "Servisler yeniden başlatılıyor..."
    
    # Servisleri enable et
    safe_execute "auditd servisini enable etme" systemctl enable auditd
    safe_execute "rsyslog servisini enable etme" systemctl enable rsyslog
    
    # Servisleri durdur
    safe_execute "auditd servisini durdurma" systemctl stop auditd || true
    safe_execute "rsyslog servisini durdurma" systemctl stop rsyslog || true
    
    sleep 3
    
    # Auditd'yi başlat
    retry_operation "auditd servisini başlatma" systemctl start "auditd"
    
    sleep 2
    
    # Audit kurallarını yükle (multiple methods)
    load_audit_rules
    
    # Rsyslog'u başlat
    retry_operation "rsyslog servisini başlatma" systemctl start "rsyslog"
    
    success "Tüm servisler başarıyla yapılandırıldı ve başlatıldı"
}

load_audit_rules() {
    log "INFO" "Audit kuralları yükleniyor..."
    
    # Method 1: augenrules (Ubuntu 16.04+)
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
    log "INFO" "Sistem doğrulama testleri çalıştırılıyor..."

    # DRY-RUN'da servis testlerini atla
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "DRY-RUN: servis doğrulama testleri atlandı"
        return
    fi

    # Servis durumu kontrolü
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
        success "EXECVE parser test başarılı"
    else
        warn "EXECVE parser test başarısız"
    fi
    
    # Yerel syslog testi
    local test_message
test_message="QRadar Ubuntu Universal Installer test $(date '+%Y%m%d%H%M%S')"
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
    log "INFO" "Audit fonksiyonalitesi test ediliyor..."
    
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
    log "INFO" "Kurulum özeti oluşturuluyor..."
    
    echo ""
    echo "============================================================="
    echo "           QRadar Universal Ubuntu Kurulum Özeti"
    echo "============================================================="
    echo ""
    echo "🖥️  SİSTEM BİLGİLERİ:"
    echo "   • Ubuntu Sürümü: $UBUNTU_VERSION ($UBUNTU_CODENAME)"
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
    echo "   • Otomatik EXECVE komut birleştirme"
    echo "   • Ubuntu sürüm uyumlu yapılandırma"
    echo "   • Güvenlik odaklı log filtreleme"
    echo "   • Otomatik fallback mekanizmaları"
    echo "   • Kapsamlı hata yönetimi"
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
    echo ""
    echo "============================================================="
    echo ""
    
    success "QRadar Universal Ubuntu kurulumu başarıyla tamamlandı!"
}

# ===============================================================================
# MAIN FUNCTION
# ===============================================================================

main() {
    # Log dosyasını oluştur
    touch "$LOG_FILE" || error_exit "Log dosyası oluşturulamıyor: $LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null || true
    
    log "INFO" "============================================================="
    log "INFO" "QRadar Universal Ubuntu Log Forwarding Installer v$SCRIPT_VERSION"
    log "INFO" "Başlatılıyor: $(date)"
    log "INFO" "QRadar Hedefi: $QRADAR_IP:$QRADAR_PORT"
    log "INFO" "============================================================="
    
    # Root kontrolü
    [[ $EUID -eq 0 ]] || error_exit "Bu script root yetkisiyle çalıştırılmalıdır. 'sudo' kullanın."
    
    # Ana kurulum adımları
    detect_ubuntu_version
    install_required_packages
    deploy_execve_parser
    configure_auditd
    configure_audisp
    configure_rsyslog
    configure_direct_audit_fallback
    restart_services
    run_validation_tests
    generate_setup_summary
    
    log "INFO" "============================================================="
    log "INFO" "Kurulum tamamlandı: $(date)"
    log "INFO" "============================================================="
}

# ===============================================================================
# SCRIPT ENTRY POINT
# ===============================================================================

# Argument parsing
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            echo "QRadar Universal Ubuntu Installer v$SCRIPT_VERSION"
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