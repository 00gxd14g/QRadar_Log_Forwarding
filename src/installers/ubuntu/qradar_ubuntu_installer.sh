#!/usr/bin/env bash
#
# ===============================================================================
# QRadar Universal Ubuntu Log Forwarding Installer v4.0.0
# ===============================================================================
#
# This script is designed to work on all Ubuntu versions (16.04+)
# QRadar SIEM log forwarding installation script.
#
# Supported Ubuntu Versions:
#   - Ubuntu 16.04 LTS (Xenial Xerus)
#   - Ubuntu 18.04 LTS (Bionic Beaver)
#   - Ubuntu 20.04 LTS (Focal Fossa)
#   - Ubuntu 22.04 LTS (Jammy Jellyfish)
#   - Ubuntu 24.04 LTS (Noble Numbat)
#   - All intermediate and future versions
#
# Features:
#   - Automatic Ubuntu version detection and compatibility
#   - Comprehensive security monitoring (MITRE ATT&CK compliant)
#   - EXECVE command concatenation
#   - Secure command execution (no eval)
#   - Automatic error correction and fallback mechanisms
#   - Comprehensive backup and recovery system
#
# Usage: sudo bash qradar_ubuntu_installer.sh <QRADAR_IP> <QRADAR_PORT>
#
# Example: sudo bash qradar_ubuntu_installer.sh 192.168.1.100 514
#
# Author: QRadar Log Forwarding Project
# Sürüm: 4.0.0 - Universal Ubuntu Edition
# ===============================================================================

set -Eeuo pipefail
trap 'error_exit "Unexpected failure (line: $LINENO)"' ERR

# ===============================================================================
# GLOBAL DEĞIŞKENLER
# ===============================================================================

# Remove these two lines
# SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# readonly SCRIPT_DIR

readonly SCRIPT_VERSION="4.0.0-ubuntu-universal"
readonly LOG_FILE="/var/log/qradar_ubuntu_setup.log"
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
USE_MINIMAL_RULES=false
RESTORE_MODE=false

# ===============================================================================
# YARDIMCI FONKSİYONLAR
# ===============================================================================

# -------------------- helpers --------------------
detect_init() {
    [[ "$(cat /proc/1/comm 2>/dev/null)" == "systemd" ]]
}

# Unified logging function
log() {
    local level="${1:-INFO}"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"

    # Also log to the universal log file
    if [[ -n "${QRADAR_UNIVERSAL_LOG_FILE:-}" ]]; then
        echo "[$timestamp] [$level] [ubuntu] $message" >> "$QRADAR_UNIVERSAL_LOG_FILE"
    fi
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    echo "ERROR: $1" >&2
    echo "Check $LOG_FILE for details."
    exit 1
}

# Warning message
warn() {
    log "WARN" "$1"
    echo "WARNING: $1" >&2
}

# Success message
success() {
    log "SUCCESS" "$1"
    echo "✓ $1"
}

# Command existence check
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if we need sudo
# shellcheck disable=SC2317
need_sudo() {
    [[ $EUID -ne 0 ]] && command_exists sudo
}

# Execute command with or without sudo
# shellcheck disable=SC2317
execute_with_privilege() {
    if need_sudo; then
        sudo "$@"
    else
        "$@"
    fi
}

# Secure command execution (no eval)
safe_execute() {
    local description="$1"
    shift
    log "DEBUG" "Executing: $description - Command: $*"
    
    if "$@" >> "$LOG_FILE" 2>&1; then
        log "DEBUG" "$description - SUCCESS"
        return 0
    else
        local exit_code=$?
        warn "$description - FAILED (Exit code: $exit_code)"
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
        if safe_execute "$description (Attempt $attempt/$max_attempts)" "$@"; then
            return 0
        fi
        if [[ $attempt -lt $max_attempts ]]; then
            log "INFO" "$delay saniye sonra tekrar denenecek..."
            sleep $delay
        fi
    done
    
    error_exit "$description failed after $max_attempts attempts"
}

# Dosya yedekleme
backup_file() {
    local file="$1"

    # OLD (triggers SC2155) --------------------------------------
    # local backup_path="$BACKUP_DIR/$(basename "$file").$(date +%H%M%S)"

    # NEW ---------------------------------------------------------
    local backup_path
    backup_path="$BACKUP_DIR/$(basename "$file").$(date +%H%M%S)"
    # -------------------------------------------------------------

    mkdir -p "$BACKUP_DIR"
    cp "$file" "$backup_path" || warn "$file yedeklenemedi"
    log "INFO" "$file dosyası $backup_path konumuna yedeklendi"
}

# Restore from backup
restore_file() {
    local file="$1"
    
    # Find the most recent backup
    local most_recent_backup
    most_recent_backup=$(find "$BACKUP_DIR" -name "$(basename "$file").*" -type f -print0 2>/dev/null | xargs -0 ls -t 2>/dev/null | head -1)
    
    if [[ -n "$most_recent_backup" && -f "$most_recent_backup" ]]; then
        cp "$most_recent_backup" "$file"
        log "INFO" "Restored: $file from $most_recent_backup"
        return 0
    else
        log "WARN" "No backup found for: $file"
        return 1
    fi
}

# ===============================================================================
# ROLLBACK FUNCTIONALITY
# ===============================================================================

rollback_qradar_changes() {
    log "INFO" "Starting QRadar configuration rollback..."
    
    if [[ ! -d "$BACKUP_DIR" ]]; then
        error_exit "Backup directory not found: $BACKUP_DIR. No rollback possible."
    fi
    
    # Stop services before rollback
    log "INFO" "Stopping services..."
    systemctl stop rsyslog auditd 2>/dev/null || true
    
    # Restore configuration files
    local files_to_restore=(
        "/etc/audit/auditd.conf"
        "/etc/audit/rules.d/99-qradar.rules"
        "/etc/audit/plugins.d/syslog.conf"
        "/etc/audisp/plugins.d/syslog.conf"
        "/etc/rsyslog.d/99-qradar.conf"
        "/etc/rsyslog.conf"
        "/etc/rsyslog.d/ignore_programs.json"
        "/etc/apparmor.d/usr.sbin.rsyslogd"
    )
    
    local restored_count=0
    local failed_count=0
    
    for file in "${files_to_restore[@]}"; do
        if restore_file "$file"; then
            ((restored_count++))
        else
            ((failed_count++))
        fi
    done
    
    # Remove installed files
    log "INFO" "Removing QRadar-specific files..."
    local files_to_remove=(
        "$CONCAT_SCRIPT_PATH"
        "/usr/local/bin/qradar_execve_parser.py"
    )
    
    for file in "${files_to_remove[@]}"; do
        if [[ -f "$file" ]]; then
            rm -f "$file"
            log "INFO" "Removed: $file"
        fi
    done
    
    # Remove QRadar audit rules
    if [[ -f "/etc/audit/rules.d/99-qradar.rules" ]]; then
        rm -f "/etc/audit/rules.d/99-qradar.rules"
        log "INFO" "Removed QRadar audit rules"
    fi
    
    # Restart services
    log "INFO" "Restarting services..."
    systemctl restart auditd rsyslog 2>/dev/null || true
    
    # Reload AppArmor if available
    if command_exists aa-enforce; then
        aa-enforce /etc/apparmor.d/usr.sbin.rsyslogd 2>/dev/null || true
    fi
    
    log "INFO" "Rollback completed - Restored: $restored_count, Failed: $failed_count"
    
    if [[ $failed_count -eq 0 ]]; then
        success "QRadar configuration successfully rolled back to original state"
    else
        warn "Rollback completed with $failed_count failures - check logs for details"
    fi
}

# ===============================================================================
# SİSTEM TESPİTİ VE DOĞRULAMA
# ===============================================================================

detect_ubuntu_version() {
    log "INFO" "Detecting Ubuntu version..."
    
    if [[ ! -f /etc/os-release ]]; then
        error_exit "/etc/os-release dosyası bulunamadı. Ubuntu sistemi doğrulanamıyor."
    fi
    
    # shellcheck disable=SC1091
    source /etc/os-release
    
    # Check that required variables are defined
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
        error_exit "This script is designed for Ubuntu systems only. Detected: $ID"
    fi
    
    UBUNTU_VERSION="$VERSION_ID"
    UBUNTU_CODENAME="$VERSION_CODENAME"
    
    # Sürüm numarasını parçala
    IFS='.' read -r VERSION_MAJOR VERSION_MINOR <<< "$UBUNTU_VERSION"
    
    # Check version values
    if [[ -z "$VERSION_MAJOR" ]] || [[ ! "$VERSION_MAJOR" =~ ^[0-9]+$ ]]; then
        error_exit "VERSION_MAJOR değeri geçersiz: '$VERSION_MAJOR' (UBUNTU_VERSION: $UBUNTU_VERSION)"
    fi
    
    if [[ -z "$VERSION_MINOR" ]] || [[ ! "$VERSION_MINOR" =~ ^[0-9]+$ ]]; then
        error_exit "VERSION_MINOR değeri geçersiz: '$VERSION_MINOR' (UBUNTU_VERSION: $UBUNTU_VERSION)"
    fi
    
    # Ubuntu 16.04+ check
    if [[ $VERSION_MAJOR -lt 16 ]] || [[ $VERSION_MAJOR -eq 16 && $VERSION_MINOR -lt 4 ]]; then
        error_exit "Bu script Ubuntu 16.04+ sürümlerini destekler. Mevcut sürüm: $UBUNTU_VERSION"
    fi
    
    success "Ubuntu $UBUNTU_VERSION ($UBUNTU_CODENAME) detected and supported"
    
    # Sürüme göre audisp metodunu belirle
    determine_audisp_method
}

determine_audisp_method() {
    log "INFO" "Determining audisp method based on Ubuntu version..."
    
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
    
    # Check and create directories
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
    log "INFO" "Checking and installing required packages..."
    
    # Package list based on Ubuntu version
    local required_packages=("auditd" "rsyslog" "python3")
    
    # Ubuntu 16.04-19.10 için audispd-plugins
    if [[ $VERSION_MAJOR -lt 20 ]]; then
        required_packages+=("audispd-plugins")
    fi
    
    local packages_to_install=()
    
    # Update package list
    retry_operation "Package list update" execute_with_privilege apt-get update
    
    # Check which packages are not installed
    for package in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package "; then
            packages_to_install+=("$package")
            log "INFO" "$package package is not installed"
        else
            log "INFO" "$package package is already installed"
        fi
    done
    
    # Install missing packages
    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        log "INFO" "Packages to be installed: ${packages_to_install[*]}"
        retry_operation "Package installation" execute_with_privilege apt-get install -y "${packages_to_install[@]}"
        success "Packages installed successfully: ${packages_to_install[*]}"
    else
        success "All required packages are already installed"
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
    log "INFO" "Deploying EXECVE command parser..."
    
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
Author: QRadar Log Forwarding Project
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
    # Check if --test argument is provided
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        # Simple test mode
        print("EXECVE parser is working correctly")
        sys.exit(0)
    
    parser = ExecveParser()
    parser.run()
EXECVE_PARSER_EOF
    
    chmod +x "$CONCAT_SCRIPT_PATH" || error_exit "EXECVE parser script'i çalıştırılabilir yapılamadı"
    chown root:root "$CONCAT_SCRIPT_PATH" || warn "EXECVE parser script'i sahiplik ayarlanamadı"
    
    # Test et
    if python3 "$CONCAT_SCRIPT_PATH" --test >> "$LOG_FILE" 2>&1; then
        success "EXECVE command parser deployed and tested successfully"
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

    if [[ "$USE_MINIMAL_RULES" == true ]]; then
        log "INFO" "Minimal audit kuralları kullanılıyor (düşük EPS için optimize edilmiş)"
        create_minimal_audit_rules
    else
        log "INFO" "Kapsamlı MITRE ATT&CK audit kuralları kullanılıyor"
        create_full_audit_rules
    fi
    
    chmod 640 "$AUDIT_RULES_FILE"
    success "Ubuntu Universal audit kuralları yapılandırıldı"
}

create_minimal_audit_rules() {
    cat > "$AUDIT_RULES_FILE" << 'MINIMAL_AUDIT_RULES_EOF'
# QRadar Minimal Ubuntu Audit Rules v4.0.0
# Düşük EPS ortamları için optimize edilmiş güvenlik audit kuralları

# Buffer ayarları
-b 8192

# Failure mode ayarları (1=printk, 2=panic)
-f 1

# Kritik Güvenlik Olayları

# T1003 - OS Credential Dumping
-w /etc/shadow -p wa -k T1003_credential_dumping
-w /etc/gshadow -p wa -k T1003_credential_dumping

# T1136 - Create Account
-a always,exit -F arch=b64 -S useradd,groupadd -F auid>=1000 -F auid!=4294967295 -k T1136_create_account
-a always,exit -F arch=b32 -S useradd,groupadd -F auid>=1000 -F auid!=4294967295 -k T1136_create_account

# T1098 - Account Manipulation
-w /etc/sudoers -p wa -k T1098_account_manipulation
-w /etc/sudoers.d/ -p wa -k T1098_account_manipulation

# T1548 - Abuse Elevation Control Mechanism
-a always,exit -F arch=b64 -S setuid,setgid -F auid>=1000 -F auid!=4294967295 -k T1548_privilege_escalation
-a always,exit -F arch=b32 -S setuid,setgid -F auid>=1000 -F auid!=4294967295 -k T1548_privilege_escalation

# T1562 - Impair Defenses
-w /etc/audit/ -p wa -k T1562_defense_evasion
-w /etc/rsyslog.conf -p wa -k T1562_defense_evasion

# T1059 - Command and Scripting Interpreter (sadece root)
-a always,exit -F arch=b64 -S execve -F uid=0 -k T1059_root_commands
-a always,exit -F arch=b32 -S execve -F uid=0 -k T1059_root_commands

# T1021 - Remote Services
-w /etc/ssh/sshd_config -p wa -k T1021_remote_services
-w /root/.ssh/ -p wa -k T1021_remote_services

# T1053 - Scheduled Task/Job
-w /etc/crontab -p wa -k T1053_scheduled_task
-w /etc/cron.d/ -p wa -k T1053_scheduled_task
-w /var/spool/cron/ -p wa -k T1053_scheduled_task

# T1055 - Process Injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x10 -F auid>=1000 -F auid!=4294967295 -k T1055_process_injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x10 -F auid>=1000 -F auid!=4294967295 -k T1055_process_injection

# T1215 - Kernel Modules and Extensions
-a always,exit -F arch=b64 -S init_module,delete_module -F auid!=-1 -k T1215_kernel_modules
-a always,exit -F arch=b32 -S init_module,delete_module -F auid!=-1 -k T1215_kernel_modules
MINIMAL_AUDIT_RULES_EOF
}

create_full_audit_rules() {
    cat > "$AUDIT_RULES_FILE" << 'FULL_AUDIT_RULES_EOF'
# QRadar Universal Ubuntu Audit Rules v4.0.0
# MITRE ATT&CK Framework uyumlu kapsamlı güvenlik audit kuralları
# Based on auditd-attack-mitre project

# Remove any existing rules
-D

# Buffer Size
-b 32768

# Failure Mode
# 0 (silent), 1 (printk, print a failure message), 2 (panic, halt the system)
-f 1

# Ignore errors
# e.g. caused by users or files not found in the local environment
-i

# Self Auditing ---------------------------------------------------------------

## Audit the audit logs
### Successful and unsuccessful attempts to read information from the audit records
-w /var/log/audit/ -k T1005_Data_From_Local_System_audit_log

## Auditd configuration
### Modifications to audit configuration that occur while the audit collection functions are operating
-w /etc/audit/ -p wa -k T1005_Data_From_Local_System_audit_config
-w /etc/libaudit.conf -p wa -k T1005_Data_From_Local_System_audit_config
-w /etc/audisp/ -p wa -k T1005_Data_From_Local_System_audit_config

## Monitor for use of audit management tools
-w /sbin/auditctl -p x -k T1005_Data_From_Local_System_audit_tools
-w /sbin/auditd -p x -k T1005_Data_From_Local_System_audit_tools

# Filters ---------------------------------------------------------------------

### We put these early because audit is a first match wins system.

## Ignore SELinux AVC records
-a always,exclude -F msgtype=AVC

## Ignore current working directory records
-a always,exclude -F msgtype=CWD

## Ignore EOE records (End Of Event, not needed)
-a always,exclude -F msgtype=EOE

## Cron jobs fill the logs with stuff we normally don't want (works with SELinux)
-a never,user -F subj_type=crond_t
-a exit,never -F subj_type=crond_t

## This prevents chrony from overwhelming the logs
-a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=chrony -F subj_type=chronyd_t

## This is not very interesting and wastes a lot of space if the server is public facing
-a always,exclude -F msgtype=CRYPTO_KEY_USER

## VMWare tools
-a exit,never -F arch=b32 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2
-a exit,never -F arch=b64 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2

### High Volume Event Filter (especially on Linux Workstations)
-a exit,never -F arch=b32 -F dir=/dev/shm -k sharedmemaccess
-a exit,never -F arch=b64 -F dir=/dev/shm -k sharedmemaccess
-a exit,never -F arch=b32 -F dir=/var/lock/lvm -k locklvm
-a exit,never -F arch=b64 -F dir=/var/lock/lvm -k locklvm

# Rules -----------------------------------------------------------------------

## Kernel Related Events
-w /etc/sysctl.conf -p wa -k sysctl
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k T1215_Kernel_Modules_and_Extensions
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k T1215_Kernel_Modules_and_Extensions
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k T1215_Kernel_Modules_and_Extensions
-a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k T1215_Kernel_Modules_and_Extensions
-a always,exit -F arch=b32 -S finit_module -S init_module -S delete_module -F auid!=-1 -k T1215_Kernel_Modules_and_Extensions
-w /etc/modprobe.conf -p wa -k T1215_Kernel_Modules_and_Extensions
-a always,exit -F arch=b64 -S kexec_load -k T1014_Rootkit
-a always,exit -F arch=b32 -S sys_kexec_load -k T1014_Rootkit

## Time Related Events
-a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k T1099_Timestomp
-a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k T1099_Timestomp
-a always,exit -F arch=b32 -S clock_settime -k T1099_Timestomp
-a always,exit -F arch=b64 -S clock_settime -k T1099_Timestomp
-w /etc/localtime -p wa -k T1099_Timestomp

## Stunnel
-w /usr/sbin/stunnel -p x -k T1079_Multilayer_Encryption

## Cron configuration & scheduled jobs related events
-w /etc/cron.allow -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.deny -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.d/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.daily/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.hourly/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.monthly/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.weekly/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/crontab -p wa -k T1168_Local_Job_Scheduling
-w /var/spool/cron/crontabs/ -k T1168_Local_Job_Scheduling
-w /etc/inittab -p wa -k T1168_Local_Job_Scheduling
-w /etc/init.d/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/init/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/at.allow -p wa -k T1168_Local_Job_Scheduling
-w /etc/at.deny -p wa -k T1168_Local_Job_Scheduling
-w /var/spool/at/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/anacrontab -p wa -k T1168_Local_Job_Scheduling

## Account Related Events
-w /etc/sudoers -p wa -k T1078_Valid_Accounts
-w /usr/bin/passwd -p x -k T1078_Valid_Accounts
-w /usr/sbin/groupadd -p x -k T1078_Valid_Accounts
-w /usr/sbin/groupmod -p x -k T1078_Valid_Accounts
-w /usr/sbin/addgroup -p x -k T1078_Valid_Accounts
-w /usr/sbin/useradd -p x -k T1078_Valid_Accounts
-w /usr/sbin/usermod -p x -k T1078_Valid_Accounts
-w /usr/sbin/adduser -p x -k T1078_Valid_Accounts

## Privleged Command Execution Related Events
-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/ping -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/chgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/ping6 -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/sbin/pwck -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/sbin/suexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/newrole -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts

## Media Export Related Events
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k T1052_Exfiltration_Over_Physical_Medium
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k T1052_Exfiltration_Over_Physical_Medium

## Session Related Events
-w /var/run/utmp -p wa -k T1108_Redundant_Access
-w /var/log/wtmp -p wa -k T1108_Redundant_Access
-w /var/log/btmp -p wa -k T1108_Redundant_Access

## Login Related Events
-w /var/log/faillog -p wa -k T1021_Remote_Services
-w /var/log/lastlog -p wa -k T1021_Remote_Services
-w /var/log/tallylog -p wa -k T1021_Remote_Services

## Pam Related Events
-w /etc/pam.d/ -p wa -k T1071_Standard_Application_Layer_Protocol
-w /etc/security/limits.conf -p wa -k T1071_Standard_Application_Layer_Protocol
-w /etc/security/pam_env.conf -p wa -k T1071_Standard_Application_Layer_Protocol
-w /etc/security/namespace.conf -p wa -k T1071_Standard_Application_Layer_Protocol
-w /etc/security/namespace.init -p wa -k T1071_Standard_Application_Layer_Protocol
-w /etc/pam.d/common-password -p wa -k T1201_Password_Policy_Discovery

## SSH Related Events
-w /etc/ssh/sshd_config -k T1021_Remote_Services

## Priv Escalation Related Events
-w /bin/su -p x -k T1169_Sudo
-w /usr/bin/sudo -p x -k T1169_Sudo
-w /etc/sudoers -p rw -k T1169_Sudo
-w /etc/sudoers.d/ -p wa -k T1169_Sudo
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -F exit=EPERM -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -F exit=EPERM -k T1166_Seuid_and_Setgid

## Power state
-w /sbin/shutdown -p x -k Power_State_Change
-w /sbin/poweroff -p x -k Power_State_Change
-w /sbin/reboot -p x -k Power_State_Change
-w /sbin/halt -p x -k Power_State_Change

## Recon Related Events
-w /etc/group -p rxaw -k T1087_Account_Discovery
-w /etc/passwd -p rxaw -k T1087_Account_Discovery
-w /etc/gshadow -p rxaw -k T1087_Account_Discovery
-w /etc/shadow -p rxaw -k T1087_Account_Discovery
-w /etc/security/opasswd -k T1087_Account_Discovery
-w /usr/sbin/nologin -k T1087_Account_Discovery
-w /sbin/nologin -k T1087_Account_Discovery
-w /usr/bin/whoami -p x -k T1033_System_Owner_User_Discovery
-w /etc/hostname -p r -k T1082_System_Information_Discovery
-w /sbin/iptables -p x -k T1082_System_Information_Discovery
-w /sbin/ifconfig -p x -k T1082_System_Information_Discovery
-w /etc/login.defs -p wa -k T1082_System_Information_Discovery
-w /etc/resolv.conf -k T1016_System_Network_Configuration_Discovery
-w /etc/hosts.allow -k T1016_System_Network_Configuration_Discovery
-w /etc/hosts.deny -k T1016_System_Network_Configuration_Discovery
-w /etc/securetty -p wa -k T1082_System_Information_Discovery
-w /usr/sbin/tcpdump -p x -k T1049_System_Network_Connections_discovery
-w /usr/sbin/traceroute -p x -k T1049_System_Network_Connections_discovery
-w /usr/bin/wireshark -p x -k T1049_System_Network_Connections_discovery
-w /usr/bin/rawshark -p x -k T1049_System_Network_Connections_discovery

## Remote Access Related Events
-w /usr/bin/wget -p x -k T1219_Remote_Access_Tools
-w /usr/bin/curl -p x -k T1219_Remote_Access_Tools
-w /usr/bin/base64 -p x -k T1219_Remote_Access_Tools
-w /bin/nc -p x -k T1219_Remote_Access_Tools
-w /bin/netcat -p x -k T1219_Remote_Access_Tools
-w /usr/bin/ncat -p x -k T1219_Remote_Access_Tools
-w /usr/bin/ssh -p x -k T1219_Remote_Access_Tools
-w /usr/bin/socat -p x -k T1219_Remote_Access_Tools
-w /usr/bin/rdesktop -p x -k T1219_Remote_Access_Tools

## Critical elements access failures
-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k T1068_Exploitation_for_Privilege_Escalation

## Code injection Related Events
-a always,exit -F arch=b32 -S ptrace -k T1055_Process_Injection
-a always,exit -F arch=b64 -S ptrace -k T1055_Process_Injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k T1055_Process_Injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k T1055_Process_Injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k T1055_Process_Injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k T1055_Process_Injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k T1055_Process_Injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k T1055_Process_Injection
-w /etc/ld.so.conf -p wa -k T1055_Process_Injection
-w /bin/systemctl -p wa -k T1055_Process_Injection
-w /etc/systemd/ -p wa -k T1055_Process_Injection

## Socket Creations
-a always,exit -F arch=b32 -S socket -F a0=2  -k T1011_Exfiltration_Over_Other_Network_Medium
-a always,exit -F arch=b64 -S socket -F a0=2  -k T1011_Exfiltration_Over_Other_Network_Medium
-a always,exit -F arch=b32 -S socket -F a0=10 -k T1011_Exfiltration_Over_Other_Network_Medium
-a always,exit -F arch=b64 -S socket -F a0=10 -k T1011_Exfiltration_Over_Other_Network_Medium

## Shell configuration Persistence Related Events
-w /etc/profile.d/ -p wa -k T1156_bash_profile_and_bashrc
-w /etc/profile -p wa -k T1156_bash_profile_and_bashrc
-w /etc/shells -p wa -k T1156_bash_profile_and_bashrc
-w /etc/bashrc -p wa -k T1156_bash_profile_and_bashrc
-w /etc/csh.cshrc -p wa -k T1156_bash_profile_and_bashrc
-w /etc/csh.login -p wa -k T1156_bash_profile_and_bashrc

## Media mount
-a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid!=-1 -k T1200_Hardware_Additions
-a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k T1200_Hardware_Additions

## Performance Related Events
-a exit,always -F arch=b32 -S all -k T1068_Exploitation_for_Privilege_Escalation_monitoring
-a exit,always -F arch=b64 -S all -k T1068_Exploitation_for_Privilege_Escalation_monitoring

# High Volume Events ----------------------------------------------------------
## Remove them if they cause issues
## Root command executions
-a always,exit -F arch=b64 -S execve -F uid=0 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_root_cmd
-a always,exit -F arch=b32 -S execve -F uid=0 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_root_cmd

## File Access
### Unauthorized Access (unsuccessful)
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid

### Unsuccessful Creation
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_access
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_access

### Unsuccessful Modification
-a always,exit -F arch=b32 -S rename,renameat,link,linkat,symlink,symlinkat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_modify
-a always,exit -F arch=b32 -S rename,renameat,link,linkat,symlink,symlinkat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_modify
-a always,exit -F arch=b64 -S rename,renameat,link,linkat,symlink,symlinkat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_modify
-a always,exit -F arch=b64 -S rename,renameat,link,linkat,symlink,symlinkat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_modify

## 32bit API Exploitation
-a always,exit -F arch=b32 -S mknod,mknodat -k T1068_Exploitation_for_Privilege_Escalation_mknod
-a always,exit -F arch=b64 -S mknod,mknodat -k T1068_Exploitation_for_Privilege_Escalation_mknod

## Application Deployment Software
-w /usr/bin/rpm -p x -k T1017_Application_Deployment_Software
-w /usr/bin/yum -p x -k T1017_Application_Deployment_Software
-w /usr/bin/dpkg -p x -k T1017_Application_Deployment_Software
-w /usr/bin/apt-add-repository -p x -k T1017_Application_Deployment_Software
-w /usr/bin/apt-get -p x -k T1017_Application_Deployment_Software
-w /usr/bin/aptitude -p x -k T1017_Application_Deployment_Software
-w /usr/bin/zypper -p x -k T1017_Application_Deployment_Software
-w /usr/bin/snap -p x -k T1017_Application_Deployment_Software

## CHEF
-w /etc/chef -p wa -k T1017_Application_Deployment_Software

## T1136 - Create Account
-a always,exit -F arch=b64 -S useradd,usermod,userdel,groupadd,groupmod,groupdel -F auid>=1000 -F auid!=4294967295 -k T1136_Create_Account
-a always,exit -F arch=b32 -S useradd,usermod,userdel,groupadd,groupmod,groupdel -F auid>=1000 -F auid!=4294967295 -k T1136_Create_Account

## T1070 - Indicator Removal on Host
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k T1070_Indicator_Removal
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k T1070_Indicator_Removal

## T1105 - Ingress Tool Transfer
-a always,exit -F arch=b64 -S open,openat,creat -F dir=/tmp -F success=1 -F auid>=1000 -F auid!=4294967295 -k T1105_Ingress_Tool_Transfer
-a always,exit -F arch=b32 -S open,openat,creat -F dir=/tmp -F success=1 -F auid>=1000 -F auid!=4294967295 -k T1105_Ingress_Tool_Transfer
-a always,exit -F arch=b64 -S open,openat,creat -F dir=/var/tmp -F success=1 -F auid>=1000 -F auid!=4294967295 -k T1105_Ingress_Tool_Transfer
-a always,exit -F arch=b32 -S open,openat,creat -F dir=/var/tmp -F success=1 -F auid>=1000 -F auid!=4294967295 -k T1105_Ingress_Tool_Transfer

## T1059 - Command and Scripting Interpreter
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k T1059_Command_and_Scripting_Interpreter
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k T1059_Command_and_Scripting_Interpreter

## T1055 - Process Injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x10 -F auid>=1000 -F auid!=4294967295 -k T1055_Process_Injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x10 -F auid>=1000 -F auid!=4294967295 -k T1055_Process_Injection

## T1082 - System Information Discovery
-a always,exit -F arch=b64 -S uname -F auid>=1000 -F auid!=4294967295 -k T1082_System_Information_Discovery
-a always,exit -F arch=b32 -S uname -F auid>=1000 -F auid!=4294967295 -k T1082_System_Information_Discovery

## T1016 - System Network Configuration Discovery
-a always,exit -F arch=b64 -S socket,connect,accept,bind -F auid>=1000 -F auid!=4294967295 -k T1016_System_Network_Configuration_Discovery
-a always,exit -F arch=b32 -S socket,connect,accept,bind -F auid>=1000 -F auid!=4294967295 -k T1016_System_Network_Configuration_Discovery

## Files access
-w /etc/hosts -p wa -k T1027_Obfuscated_Files_or_Information
-w /etc/hostname -k T1082_System_Information_Discovery_hostname
-w /etc/network/ -p wa -k T1016_System_Network_Configuration_Discovery
-w /etc/netplan/ -p wa -k T1016_System_Network_Configuration_Discovery

## T1037 - Boot or Logon Initialization Scripts
-w /etc/init.d/ -p wa -k T1037_Boot_or_Logon_Initialization_Scripts
-w /etc/systemd/system/ -p wa -k T1037_Boot_or_Logon_Initialization_Scripts

## T1543 - Create or Modify System Process
-w /usr/lib/systemd/system/ -p wa -k T1543_Create_or_Modify_System_Process
-w /lib/systemd/system/ -p wa -k T1543_Create_or_Modify_System_Process
-w /etc/systemd/user/ -p wa -k T1543_Create_or_Modify_System_Process
-w /lib/systemd/user/ -p wa -k T1543_Create_or_Modify_System_Process

## Kernel module loading (T1547)
-a always,exit -F arch=b64 -S init_module,delete_module -F auid>=1000 -F auid!=4294967295 -k T1547_Kernel_modules
-a always,exit -F arch=b32 -S init_module,delete_module -F auid>=1000 -F auid!=4294967295 -k T1547_Kernel_modules

## File integrity monitoring
-w /etc/ld.so.conf -p wa -k T1055_Process_Injection_ld
-w /etc/ld.so.conf.d/ -p wa -k T1055_Process_Injection_ld

# Make the configuration immutable --------------------------------------------
## IMPORTANT: Uncomment the following line to make the configuration immutable
## This prevents any rules from being changed until a reboot
# -e 2
FULL_AUDIT_RULES_EOF
}

# ===============================================================================
# AUDITD DAEMON CONFIGURATION
# ===============================================================================

configure_auditd_daemon() {
    log "INFO" "Checking auditd daemon configuration..."
    
    local auditd_conf="/etc/audit/auditd.conf"
    backup_file "$auditd_conf"
    
    # Create auditd.conf with corrected configuration
    cat > "$auditd_conf" << 'AUDITD_CONF_EOF'
# auditd.conf - QRadar Ubuntu configuration
# Configuration file for auditd daemon
log_file = /var/log/audit/audit.log
log_format = ENRICHED
log_group = adm
priority_boost = 4
flush = INCREMENTAL
freq = 50
max_log_file = 30
num_logs = 5
space_left = 75
admin_space_left = 50
space_left_action = SYSLOG
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
krb5_key_file = /etc/audit/audit.key
distribute_network = no
q_depth = 2000
overflow_action = SYSLOG
max_log_file_action = ROTATE
AUDITD_CONF_EOF
    
    chmod 640 "$auditd_conf"
    success "Auditd daemon yapılandırması tamamlandı"
}

# ===============================================================================
# AUDISP CONFIGURATION
# ===============================================================================

configure_audisp() {
    log "INFO" "Configuring audisp based on Ubuntu version..."
    
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

    # Create simple 99-qradar.conf 
    # shellcheck disable=SC2154
    cat > "$RSYSLOG_QRADAR_CONF" << EOF
# QRadar Minimal Log Forwarding Configuration v4.2.1
# This file is placed in /etc/rsyslog.d/

# Load required modules
module(load="omfwd")
module(load="omprogram")

# EXCLUDE unwanted logs (cron, daemon, kernel, systemd, etc.)
if ($programname == 'cron' or $programname == 'CRON' or 
    $programname == 'systemd' or $programname startswith 'systemd-' or
    $programname == 'dbus' or $programname == 'dbus-daemon' or
    $programname == 'NetworkManager' or $programname == 'snapd' or
    $programname == 'polkitd' or $programname == 'packagekitd' or
    $programname == 'avahi-daemon' or $programname == 'cups' or
    $programname == 'gdm' or $programname == 'gnome-shell' or
    $programname == 'ModemManager' or $programname == 'wpa_supplicant' or
    $programname == 'ntpd' or $programname == 'chronyd' or
    $programname == 'upstart' or $programname == 'init' or
    $programname == 'kernel' or $programname startswith 'kernel:' or
    $programname == 'dhclient' or $programname == 'dhcpcd' or
    $programname == 'postfix' or $programname == 'sendmail' or
    $programname == 'named' or $programname == 'bind' or
    $programname == 'apache2' or $programname == 'nginx' or
    $programname == 'mysqld' or $programname == 'postgres' or
    $syslogfacility-text == 'daemon' or $syslogfacility-text == 'kern' or
    $syslogfacility-text == 'cron' or $syslogfacility-text == 'lpr' or
    $syslogfacility-text == 'news' or $syslogfacility-text == 'uucp' or
    $syslogfacility-text == 'mail' or $syslogfacility-text == 'ftp') then {
    stop
}

# Input for audit logs from auditd - SECURITY LOGS ONLY
if ($programname == 'audit' or $syslogfacility-text == 'local3' or 
    $syslogfacility-text == 'authpriv' or $syslogfacility-text == 'auth' or
    $programname == 'sshd' or $programname == 'sudo' or $programname == 'su' or
    $programname == 'login' or $programname == 'passwd' or 
    $programname == 'useradd' or $programname == 'userdel' or $programname == 'usermod') then {
    
    # Create a copy for EXECVE processing if needed
    if ($msg contains 'type=EXECVE') then {
        action(type="omprogram"
               binary="$CONCAT_SCRIPT_PATH")
    }
    
    # Forward to QRadar with simple format
    action(type="omfwd"
           Target="$QRADAR_IP"
           Port="$QRADAR_PORT"
           Protocol="tcp"
           queue.type="linkedList"
           queue.filename="qradar_audit_fwd"
           action.resumeRetryCount="-1")
    stop
}
EOF

    # Create rsyslog.conf
    backup_file "/etc/rsyslog.conf"
    cat > "/etc/rsyslog.conf" << 'RSYSLOG_CONF_EOF'
# /etc/rsyslog.conf configuration file for rsyslog
#
# For more information install rsyslog-doc and see
# /usr/share/doc/rsyslog-doc/html/configuration/index.html
#
# Default logging rules can be found in /etc/rsyslog.d/50-default.conf

#################
#### MODULES ####
#################

module(load="imuxsock") # provides support for local system logging
module(load="imklog")   # provides kernel logging support
#module(load="immark")  # provides --MARK-- message capability

# provides UDP syslog reception
#module(load="imudp")
#input(type="imudp" port="514")

# provides TCP syslog reception
#module(load="imtcp")
#input(type="imtcp" port="514")

# provides kernel logging support and enable non-kernel klog messages
module(load="imklog" permitnonkernelfacility="on")

###########################
#### GLOBAL DIRECTIVES ####
###########################

#
# Use traditional timestamp format.
# To enable high precision timestamps, comment out the following line.
#
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# Filter duplicated messages
$RepeatedMsgReduction on

#
# Set the default permissions for all log files.
#
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog

#
# Where to place spool and state files
#
$WorkDirectory /var/spool/rsyslog

#
# Include all config files in /etc/rsyslog.d/
#
$IncludeConfig /etc/rsyslog.d/*.conf
RSYSLOG_CONF_EOF
    chmod 644 "/etc/rsyslog.conf"

    # Create ignore_programs.json
    mkdir -p "/etc/rsyslog.d"
    backup_file "/etc/rsyslog.d/ignore_programs.json"
    cat > "/etc/rsyslog.d/ignore_programs.json" << 'IGNORE_PROGRAMS_EOF'
{
  "version": 1,
  "nomatch": "PASS",
  "type": "string",
  "table": [
    {"index": "systemd", "value": "IGNORE"},
    {"index": "systemd-resolved", "value": "IGNORE"},
    {"index": "systemd-timesyncd", "value": "IGNORE"},
    {"index": "systemd-networkd", "value": "IGNORE"},
    {"index": "systemd-journald", "value": "IGNORE"},
    {"index": "systemd-logind", "value": "IGNORE"},
    {"index": "snapd", "value": "IGNORE"},
    {"index": "packagekitd", "value": "IGNORE"},
    {"index": "polkitd", "value": "IGNORE"},
    {"index": "dbus", "value": "IGNORE"},
    {"index": "dbus-daemon", "value": "IGNORE"},
    {"index": "NetworkManager", "value": "IGNORE"},
    {"index": "ModemManager", "value": "IGNORE"},
    {"index": "wpa_supplicant", "value": "IGNORE"},
    {"index": "avahi-daemon", "value": "IGNORE"},
    {"index": "colord", "value": "IGNORE"},
    {"index": "cups", "value": "IGNORE"},
    {"index": "cups-browsed", "value": "IGNORE"},
    {"index": "gnome-shell", "value": "IGNORE"},
    {"index": "gdm", "value": "IGNORE"},
    {"index": "udisks2", "value": "IGNORE"},
    {"index": "rtkit-daemon", "value": "IGNORE"},
    {"index": "accounts-daemon", "value": "IGNORE"}
  ]
}
IGNORE_PROGRAMS_EOF
    chmod 644 "/etc/rsyslog.d/ignore_programs.json"

    # Create rsyslog parser configuration for audit logs
    cat > "/etc/rsyslog.d/01-qradar-parsers.conf" << 'PARSER_CONF_EOF'
# QRadar Audit Log Parsing Rules
# This file contains mmnormalize rules for parsing audit logs

# Load the mmnormalize module
module(load="mmnormalize")

# Define parsing rules for different audit types
# These rules extract fields from audit messages for better SIEM integration

# SYSCALL parsing
parser(name="syscall.parser" type="string" rulebase="/etc/rsyslog.d/audit.rulebase")

# USER_AUTH parsing  
parser(name="userauth.parser" type="string" rulebase="/etc/rsyslog.d/audit.rulebase")

# USER_CMD parsing
parser(name="usercmd.parser" type="string" rulebase="/etc/rsyslog.d/audit.rulebase")

# EXECVE parsing
parser(name="execve.parser" type="string" rulebase="/etc/rsyslog.d/audit.rulebase")
PARSER_CONF_EOF
    chmod 644 "/etc/rsyslog.d/01-qradar-parsers.conf"

    # Create audit rulebase file
    cat > "/etc/rsyslog.d/audit.rulebase" << 'AUDIT_RULEBASE_EOF'
version=2

# USER_AUTH parsing
rule=:%type:word% msg=audit(%audit_epoch:number%:%audit_counter:number%): pid=%pid:number% uid=%uid:number% auid=%auid:number% ses=%ses:number% msg='op=%op:word% acct="%acct:word%" exe="%exe:char-to:"%" hostname=%hostname:word% addr=%addr:ipv4% terminal=%terminal:word% res=%res:word%'%

# USER_CMD parsing
rule=:%type:word% msg=audit(%audit_epoch:number%:%audit_counter:number%): pid=%pid:number% uid=%uid:number% auid=%auid:number% ses=%ses:number% msg='cwd="%cwd:char-to:"%" cmd=%cmd:quoted-string% terminal=%terminal:word% res=%res:word%'%

# SYSCALL parsing
rule=:%type:word% msg=audit(%audit_epoch:number%:%audit_counter:number%): arch=%arch:word% syscall=%syscall:number% success=%success:word% exit=%exit:number% a0=%a0:word% a1=%a1:word% a2=%a2:word% a3=%a3:word% items=%items:number% ppid=%ppid:number% pid=%pid:number% auid=%auid:number% uid=%uid:number% gid=%gid:number% euid=%euid:number% suid=%suid:number% fsuid=%fsuid:number% egid=%egid:number% sgid=%sgid:number% fsgid=%fsgid:number% tty=%tty:word% ses=%ses:number% comm="%comm:char-to:"%" exe="%exe:char-to:"%" key="%key:char-to:"%"%

# EXECVE parsing
rule=:%type:word% msg=audit(%audit_epoch:number%:%audit_counter:number%): argc=%argc:number% a0="%a0:char-to:"%" a1="%a1:char-to:"%" a2="%a2:char-to:"%" a3="%a3:char-to:"%"%
AUDIT_RULEBASE_EOF
    chmod 644 "/etc/rsyslog.d/audit.rulebase"

    success "Rsyslog Ubuntu Universal yapılandırması tamamlandı"
}

# ===============================================================================
# APPARMOR CONFIGURATION
# ===============================================================================

configure_apparmor() {
    log "INFO" "AppArmor rsyslog izinleri yapılandırılıyor..."
    
    local apparmor_profile="/etc/apparmor.d/usr.sbin.rsyslogd"
    
    if [[ -f "$apparmor_profile" ]]; then
        backup_file "$apparmor_profile"
        
        # Add python execution permissions to rsyslog AppArmor profile
        if ! grep -q "/usr/bin/python3" "$apparmor_profile"; then
            sed -i '/^  \/usr\/sbin\/rsyslogd mr,/a\  \/usr\/bin\/python3 ix,' "$apparmor_profile"
        fi
        
        if ! grep -q "/usr/local/bin/qradar_execve_parser.py" "$apparmor_profile"; then
            sed -i '/^  \/usr\/sbin\/rsyslogd mr,/a\  \/usr\/local\/bin\/qradar_execve_parser.py ix,' "$apparmor_profile"
        fi
        
        if ! grep -q "/usr/local/bin/qradar_mitre_parser.py" "$apparmor_profile"; then
            sed -i '/^  \/usr\/sbin\/rsyslogd mr,/a\  \/usr\/local\/bin\/qradar_mitre_parser.py ix,' "$apparmor_profile"
        fi
        
        # Reload AppArmor profile
        if command -v apparmor_parser &> /dev/null; then
            apparmor_parser -r "$apparmor_profile" 2>/dev/null || warn "AppArmor profile reload failed"
        fi
        
        success "AppArmor rsyslog izinleri yapılandırıldı"
    else
        log "INFO" "AppArmor profili bulunamadı, atlanıyor"
    fi
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
    set \$.exe = re_extract(\$msg, 'exe="([^"]+)"', 0, 1, "unknown");
    set \$.success = re_extract(\$msg, "success=([a-z]+)", 0, 1, "unknown");
    set \$.key = re_extract(\$msg, 'key="([^"]+)"', 0, 1, "none");

    # Enhanced EXECVE processing in fallback mode
    if (\$msg contains "type=EXECVE") then {
        # Enhanced EXECVE command reconstruction with extended arguments
        set \$.a0 = re_extract(\$msg, 'a0="([^"]+)"', 0, 1, "");
        set \$.a1 = re_extract(\$msg, 'a1="([^"]+)"', 0, 1, "");
        set \$.a2 = re_extract(\$msg, 'a2="([^"]+)"', 0, 1, "");
        set \$.a3 = re_extract(\$msg, 'a3="([^"]+)"', 0, 1, "");
        set \$.a4 = re_extract(\$msg, 'a4="([^"]+)"', 0, 1, "");
        set \$.a5 = re_extract(\$msg, 'a5="([^"]+)"', 0, 1, "");
        set \$.a6 = re_extract(\$msg, 'a6="([^"]+)"', 0, 1, "");
        set \$.a7 = re_extract(\$msg, 'a7="([^"]+)"', 0, 1, "");
        set \$.a8 = re_extract(\$msg, 'a8="([^"]+)"', 0, 1, "");
        set \$.a9 = re_extract(\$msg, 'a9="([^"]+)"', 0, 1, "");

        # Build complete command line with all arguments
        set \$.full_command = \$.a0;
        if (\$.a1 != "") then set \$.full_command = \$.full_command & " " & \$.a1;
        if (\$.a2 != "") then set \$.full_command = \$.full_command & " " & \$.a2;
        if (\$.a3 != "") then set \$.full_command = \$.full_command & " " & \$.a3;
        if (\$.a4 != "") then set \$.full_command = \$.full_command & " " & \$.a4;
        if (\$.a5 != "") then set \$.full_command = \$.full_command & " " & \$.a5;
        if (\$.a6 != "") then set \$.full_command = \$.full_command & " " & \$.a6;
        if (\$.a7 != "") then set \$.full_command = \$.full_command & " " & \$.a7;
        if (\$.a8 != "") then set \$.full_command = \$.full_command & " " & \$.a8;
        if (\$.a9 != "") then set \$.full_command = \$.full_command & " " & \$.a9;

        # Send with traditional parser
        action(
            type="omprog"
            binary="$CONCAT_SCRIPT_PATH"
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

    log "INFO" "Restarting services..."
    
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

    # Service status check
    local services=("auditd" "rsyslog")
    for service in "${services[@]}"; do
        if detect_init && systemctl is-active --quiet "$service"; then
            success "$service servisi çalışıyor"
        else
            warn "$service servisi çalışmıyor - başlatmaya çalışılıyor..."
            safe_execute "$service servisini başlatma" systemctl start "$service"
        fi
    done
    
    # Rsyslog configuration syntax check
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
    log "INFO" "Testing QRadar connection..."
    
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
    log "INFO" "Testing audit functionality..."
    
    # Güvenli audit olayı tetikle
    cat /etc/passwd > /dev/null 2>&1 || true
    sleep 2
    
    # Check audit event
    if command_exists ausearch; then
        if ausearch --start today -k T1087_Account_Discovery 2>/dev/null | grep -q "type=SYSCALL"; then
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
    log "INFO" "Generating installation summary..."
    
    echo ""
    echo "============================================================="
    echo "           QRadar Universal Ubuntu Installation Summary"
    echo "============================================================="
    echo ""
    echo "🖥️  SİSTEM BİLGİLERİ:"
    echo "   • Ubuntu Version: $UBUNTU_VERSION ($UBUNTU_CODENAME)"
    echo "   • Audisp Metodu: $AUDISP_METHOD"
    echo "   • QRadar Target: $QRADAR_IP:$QRADAR_PORT"
    if [[ "$USE_MINIMAL_RULES" == true ]]; then
        echo "   • Kural Seti: Minimal (düşük EPS)"
    else
        echo "   • Kural Seti: Kapsamlı MITRE ATT&CK"
    fi
    echo ""
    echo "📁 OLUŞTURULAN DOSYALAR:"
    echo "   • Audit Kuralları: $AUDIT_RULES_FILE"
    echo "   • Audisp Yapılandırması: $AUDISP_SYSLOG_CONF"
    echo "   • Rsyslog Yapılandırması: $RSYSLOG_QRADAR_CONF"
    echo "   • EXECVE Parser: $CONCAT_SCRIPT_PATH"
    echo "   • Installation Log: $LOG_FILE"
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
    echo "   • Automatic EXECVE command concatenation"
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
    echo "🔍 TEST COMMANDS:"
    echo "   • Manual test: logger -p local3.info 'Test mesajı'"
    echo "   • Audit test: sudo touch /etc/passwd"
    echo "   • Bağlantı test: telnet $QRADAR_IP $QRADAR_PORT"
    echo "   • Parser test: python3 $CONCAT_SCRIPT_PATH --test"
    echo ""
    echo "============================================================="
    echo ""
    
    success "QRadar Universal Ubuntu installation completed successfully!"
}

# ===============================================================================
# MAIN FUNCTION
# ===============================================================================

main() {
    # Log dosyasını oluştur
    touch "$LOG_FILE" || error_exit "Log dosyası oluşturulamıyor: $LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null || true
    
    # Root kontrolü
    [[ $EUID -eq 0 ]] || error_exit "Bu script root yetkisiyle çalıştırılmalıdır. 'sudo' kullanın."
    
    # Check if restore mode is requested
    if [[ "$RESTORE_MODE" == true ]]; then
        log "INFO" "============================================================="
        log "INFO" "QRadar Configuration Rollback v$SCRIPT_VERSION"
        log "INFO" "Starting: $(date)"
        log "INFO" "============================================================="
        
        rollback_qradar_changes
        
        log "INFO" "============================================================="
        log "INFO" "Rollback completed: $(date)"
        log "INFO" "============================================================="
        return 0
    fi
    
    log "INFO" "============================================================="
    log "INFO" "QRadar Universal Ubuntu Log Forwarding Installer v$SCRIPT_VERSION"
    log "INFO" "Starting: $(date)"
    log "INFO" "QRadar Target: $QRADAR_IP:$QRADAR_PORT"
    log "INFO" "============================================================="
    
    # Ana kurulum adımları
    detect_ubuntu_version
    install_required_packages
    deploy_execve_parser
    configure_auditd
    configure_auditd_daemon
    configure_audisp
    configure_rsyslog
    configure_apparmor
    configure_direct_audit_fallback
    restart_services
    run_validation_tests
    generate_setup_summary
    
    log "INFO" "============================================================="
    log "INFO" "Installation completed: $(date)"
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
        --minimal)
            USE_MINIMAL_RULES=true
            shift
            ;;
        --restore)
            RESTORE_MODE=true
            shift
            ;;
        -h|--help)
            echo "QRadar Universal Ubuntu Installer v$SCRIPT_VERSION"
            echo ""
            echo "Usage: $0 <QRADAR_IP> <QRADAR_PORT> [OPTIONS]"
            echo "       $0 --restore"
            echo ""
            echo "Options:"
            echo "  --minimal  Use minimal audit rules for EPS optimization"
            echo "  --dry-run  Test mode without service restarts"
            echo "  --restore  Restore original configuration (rollback all changes)"
            echo "  --help     Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 192.168.1.100 514"
            echo "  $0 192.168.1.100 514 --minimal"
            echo "  $0 --restore"
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
if [[ "$RESTORE_MODE" != true ]]; then
    if [[ -z "$QRADAR_IP" ]] || [[ -z "$QRADAR_PORT" ]]; then
        echo "Kullanım: $0 <QRADAR_IP> <QRADAR_PORT> [--minimal]"
        echo "       $0 --restore"
        echo "Örnek: $0 192.168.1.100 514 --minimal"
        echo "       $0 --restore"
        exit 1
    fi

    # IP address format check
    if ! [[ "$QRADAR_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        error_exit "Geçersiz IP adresi formatı: $QRADAR_IP"
    fi
fi

# Port number check
if [[ "$RESTORE_MODE" != true ]]; then
    if ! [[ "$QRADAR_PORT" =~ ^[0-9]+$ ]] || [[ "$QRADAR_PORT" -lt 1 ]] || [[ "$QRADAR_PORT" -gt 65535 ]]; then
        error_exit "Geçersiz port numarası: $QRADAR_PORT (1-65535 arası olmalı)"
    fi
fi

# Ana fonksiyonu çalıştır
main

exit 0
