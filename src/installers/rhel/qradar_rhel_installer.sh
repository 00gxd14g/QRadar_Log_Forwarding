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
readonly RESOURCE_DIR="${SCRIPT_DIR}/../universal"
readonly SCRIPT_VERSION="4.0.0-rhel-universal"
readonly LOG_FILE="/var/log/qradar_rhel_setup.log"
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
MINIMAL_RULES=false
OPEN_PORT=false
DRY_RUN=false

# ===============================================================================
# YARDIMCI FONKSİYONLAR
# ===============================================================================

# -------------------- helpers --------------------
detect_init() {
    [[ "$(cat /proc/1/comm 2>/dev/null)" == "systemd" ]]
    return 0
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
        echo "[$timestamp] [$level] [rhel] $message" >> "$QRADAR_UNIVERSAL_LOG_FILE"
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

# Komut varlığı kontrolü
command_exists() {
    command -v "$1" >/dev/null 2>&1
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

# Retry mechanism
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
            log "INFO" "Retrying in $delay seconds..."
            sleep $delay
        fi
    done
    
    error_exit "$description failed after $max_attempts attempts"
}

# Dosya yedekleme
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_path="$BACKUP_DIR/$(basename "$file").$(date +%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp --preserve=mode,ownership,timestamps "$file" "$backup_path" \
          || warn "Could not backup $file"
        log "INFO" "Backed up $file → $backup_path"
    fi
}


# ===============================================================================
# SİSTEM TESPİTİ VE DOĞRULAMA
# ===============================================================================

detect_rhel_family() {
    log "INFO" "Detecting RHEL family distribution..."
    
    [[ -d "$RESOURCE_DIR" ]] || error_exit "Resource directory $RESOURCE_DIR missing"

    if [[ ! -f /etc/os-release ]]; then
        error_exit "/etc/os-release file not found. Cannot verify RHEL system."
    fi
    
    # shellcheck source=/etc/os-release
    source /etc/os-release
    
    # Check for required variables
    if [[ -z "${ID:-}" ]]; then
        error_exit "ID variable not found in /etc/os-release"
    fi
    
    if [[ -z "${PRETTY_NAME:-}" ]]; then
        error_exit "PRETTY_NAME variable not found in /etc/os-release"
    fi
    
    DISTRO_ID="$ID"
    DISTRO_NAME="$PRETTY_NAME"
    
    # RHEL family check
    case "$DISTRO_ID" in
        "rhel"|"centos"|"rocky"|"almalinux"|"ol"|"amzn"|"ubuntu")
            log "INFO" "RHEL family distribution detected: $DISTRO_ID"
            ;;
        *)
            if [[ "${CI:-}" == "true" ]]; then
                warn "CI mode: skipping distro check"
            else
                error_exit "This script is only for RHEL family distributions. Detected: $DISTRO_ID"
            fi
            ;;
    esac
    
    # Extract version information
    if [[ -n "$VERSION_ID" ]]; then
        VERSION_MAJOR="${VERSION_ID%%.*}"
        VERSION_MINOR="${VERSION_ID#*.}"
        VERSION_MINOR="${VERSION_MINOR%%.*}"
    else
        # For cases like CentOS Stream
        VERSION_MAJOR="8"
        VERSION_MINOR="0"
        warn "VERSION_ID not found, using default: $VERSION_MAJOR.$VERSION_MINOR"
    fi
    
    # Check version values
    if [[ -z "$VERSION_MAJOR" ]] || [[ ! "$VERSION_MAJOR" =~ ^[0-9]+$ ]]; then
        error_exit "Invalid VERSION_MAJOR: '$VERSION_MAJOR' (from VERSION_ID: $VERSION_ID)"
    fi
    
    if [[ -z "$VERSION_MINOR" ]] || [[ ! "$VERSION_MINOR" =~ ^[0-9]+$ ]]; then
        error_exit "Invalid VERSION_MINOR: '$VERSION_MINOR' (from VERSION_ID: $VERSION_ID)"
    fi
    
    # RHEL 7+ check
    if [[ $VERSION_MAJOR -lt 7 ]]; then
        error_exit "This script supports RHEL 7+ versions. Current version: $VERSION_MAJOR"
    fi
    
    success "$DISTRO_NAME detected and supported (Version: $VERSION_MAJOR.$VERSION_MINOR)"
    
    # Paket yöneticisini belirle
    determine_package_manager
    
    # Sistem özelliklerini kontrol et
    check_system_features
}

determine_package_manager() {
    log "INFO" "Determining package manager..."
    
    # RHEL 8+, CentOS 8+, Rocky, AlmaLinux -> DNF
    # RHEL 7, CentOS 7 -> YUM
    # Amazon Linux 2 -> YUM
    
    if [[ "$DISTRO_ID" == "amzn" ]]; then
        PACKAGE_MANAGER="yum"
        log "INFO" "Amazon Linux detected, using YUM"
    elif [[ "$DISTRO_ID" == "ubuntu" ]]; then
        PACKAGE_MANAGER="apt-get"
        log "INFO" "Ubuntu detected, using apt-get"
    elif [[ $VERSION_MAJOR -ge 8 ]]; then
        if command_exists dnf; then
            PACKAGE_MANAGER="dnf"
            log "INFO" "Using DNF package manager"
        else
            PACKAGE_MANAGER="yum"
            log "INFO" "DNF not found, using YUM"
        fi
    else
        PACKAGE_MANAGER="yum"
        log "INFO" "Using YUM package manager (RHEL 7)"
    fi
}

check_system_features() {
    log "INFO" "Checking system features..."
    
    # SELinux check
    if command_exists getenforce; then
        local selinux_status
        selinux_status="$(getenforce 2>/dev/null || echo 'Disabled')"
        if [[ "$selinux_status" != "Disabled" ]]; then
            HAS_SELINUX=true
            log "INFO" "SELinux is active: $selinux_status"
        else
            log "INFO" "SELinux is disabled"
        fi
    fi
    
    # Firewalld check
    if systemctl is-enabled firewalld >/dev/null 2>&1; then
        HAS_FIREWALLD=true
        log "INFO" "Firewalld is active"
    else
        log "INFO" "Firewalld is disabled or not installed"
    fi
    
    # Check for syslog file
    if [[ -f "/var/log/messages" ]]; then
        SYSLOG_FILE="/var/log/messages"
    elif [[ -f "/var/log/syslog" ]]; then
        SYSLOG_FILE="/var/log/syslog"
    fi
    
    log "INFO" "Syslog file: $SYSLOG_FILE"
}

# ===============================================================================
# PAKET KURULUMU
# ===============================================================================

install_required_packages() {
    log "INFO" "Checking and installing required packages for RHEL family..."

    # Package list for RHEL family
    local required_packages=("auditd" "rsyslog" "python3")
    
    if [[ "$DISTRO_ID" == "ubuntu" ]]; then
        required_packages=("auditd" "rsyslog" "python3")
    fi
    
    # audispd-plugins for RHEL/CentOS 7
    if [[ $VERSION_MAJOR -eq 7 ]]; then
        required_packages+=("audispd-plugins")
    fi
    
    local packages_to_install=()
    
    # Check which packages are not installed
    for package in "${required_packages[@]}"; do
        if ! rpm -q "$package" >/dev/null 2>&1; then
            packages_to_install+=("$package")
            log "INFO" "$package is not installed"
        else
            log "INFO" "$package is already installed"
        fi
    done
    
    # Install missing packages
    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        log "INFO" "Packages to be installed: ${packages_to_install[*]}"
        
        # EPEL repository might be needed (especially for RHEL 7)
        if [[ $VERSION_MAJOR -eq 7 ]] && ! rpm -q epel-release >/dev/null 2>&1; then
            log "INFO" "Installing EPEL repository..."
            safe_execute "EPEL repository installation" "$PACKAGE_MANAGER" install -y epel-release || warn "EPEL installation failed"
        fi
        
        if [[ "$DISTRO_ID" == "ubuntu" ]]; then
            retry_operation "Package installation" sudo "$PACKAGE_MANAGER" update
        fi
        retry_operation "Package installation" sudo "$PACKAGE_MANAGER" install -y "${packages_to_install[@]}"
        success "Packages installed successfully: ${packages_to_install[*]}"
    else
        success "All required packages are already installed"
    fi
    
    # Verify critical binaries
    local critical_binaries=("/sbin/auditd" "/usr/sbin/rsyslogd" "/usr/bin/python3")
    for binary in "${critical_binaries[@]}"; do
        if [[ ! -f "$binary" ]]; then
            error_exit "Critical binary not found: $binary"
        fi
    done
    
    success "All critical binaries verified"
}


# ===============================================================================
# PYTHON PARSER SCRIPT
# ===============================================================================

deploy_execve_parser() {
    log "INFO" "Deploying EXECVE command parser for RHEL family..."
    
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
    
    chmod +x "$CONCAT_SCRIPT_PATH" || error_exit "Failed to make EXECVE parser script executable"
    chown root:root "$CONCAT_SCRIPT_PATH" || warn "Failed to set ownership of EXECVE parser script"

    # Test it
    if python3 - "$CONCAT_SCRIPT_PATH" <<'PYEOF'; then
import importlib.util, sys, pathlib, io
parser_path = sys.argv[1]
spec = importlib.util.spec_from_file_location("parser", parser_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
sample = 'type=EXECVE argc=2 a0="cat" a1="/etc/shadow" uid=0 gid=0'
print(mod.ExecveParser().parse_line(sample))
PYEOF
        success "EXECVE command parser deployed and tested successfully for RHEL family"
    else
        warn "EXECVE parser test failed, but the script was deployed"
    fi

    # Deploy helper scripts
    cat > "/usr/local/bin/extract_audit_type.sh" << 'AUDIT_TYPE_EOF'
#!/bin/bash
# Extract audit log type
echo "$1" | grep -oP 'type=\K\w+' | head -1
AUDIT_TYPE_EOF
    chmod +x "/usr/local/bin/extract_audit_type.sh"
    chown root:root "/usr/local/bin/extract_audit_type.sh"

    cat > "/usr/local/bin/extract_audit_result.sh" << 'AUDIT_RESULT_EOF'
#!/bin/bash
# Extract audit log result
if echo "$1" | grep -q "res=success\|success=yes"; then
    echo "success"
else
    echo "failed"
fi
AUDIT_RESULT_EOF
    chmod +x "/usr/local/bin/extract_audit_result.sh"
    chown root:root "/usr/local/bin/extract_audit_result.sh"
    
    success "Helper scripts deployed successfully"
}

# ===============================================================================
# AUDIT CONFIGURATION
# ===============================================================================

configure_auditd() {
    log "INFO" "Configuring auditd rules for RHEL family..."
    
    backup_file "$AUDIT_RULES_FILE"
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")"

    if [[ "$MINIMAL_RULES" == true ]]; then
        log "INFO" "Using minimal audit rules"
        cp "${RESOURCE_DIR}/audit-minimal.rules" "$AUDIT_RULES_FILE"
    else
        cp "${RESOURCE_DIR}/audit.rules" "$AUDIT_RULES_FILE"
    fi
    
    chmod 640 "$AUDIT_RULES_FILE"
    success "Universal audit rules configured for RHEL family"
}

# ===============================================================================
# AUDIT PLUGIN CONFIGURATION
# ===============================================================================

configure_audit_plugins() {
    log "INFO" "Configuring audit plugins for RHEL family..."
    
    backup_file "$AUDIT_SYSLOG_CONF"
    mkdir -p "$AUDIT_PLUGINS_DIR"
    
    # Audit syslog plugin for RHEL family
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
    success "Audit syslog plugin configured for RHEL family"
}

# ===============================================================================
# SELINUX CONFIGURATION
# ===============================================================================

configure_selinux() {
    if [[ "$HAS_SELINUX" == true ]]; then
        log "INFO" "Applying SELinux configuration..."
        
        # Allow rsyslog network connection
        if command_exists setsebool; then
            safe_execute "Set SELinux rsyslog network boolean" setsebool -P rsyslog_can_network_connect on
            success "SELinux rsyslog network connection enabled"
        fi
        
        # Set SELinux context for Python script
        if command_exists restorecon; then
            safe_execute "Set Python script SELinux context" restorecon -R "$CONCAT_SCRIPT_PATH"
            success "Python script SELinux context set"
        fi
        
        # Context for audit log files
        if command_exists restorecon; then
            safe_execute "Set audit log SELinux context" restorecon -R /var/log/audit/
        fi
        
        log "INFO" "SELinux configuration complete"
    else
        log "INFO" "SELinux is disabled, skipping configuration"
    fi
}

# ===============================================================================
# FIREWALL CONFIGURATION
# ===============================================================================

configure_firewall() {
    if [[ "$HAS_FIREWALLD" == true ]] && [[ "$OPEN_PORT" == true ]]; then
        log "INFO" "Applying firewalld configuration..."
        
        # Allow outgoing connections for QRadar port
        if systemctl is-active --quiet firewalld; then
            if safe_execute "Open QRadar port in firewalld" firewall-cmd --permanent --add-port="${QRADAR_PORT}/tcp"; then
                safe_execute "Reload firewalld" firewall-cmd --reload
                success "QRadar port ($QRADAR_PORT/tcp) opened in firewalld"
            else
                warn "Firewalld configuration failed"
            fi
        else
            warn "firewalld not active; skipping port open"
        fi
        
        log "INFO" "Firewalld configuration complete"
    else
        log "INFO" "Firewalld configuration skipped"
    fi
}

# ===============================================================================
# RSYSLOG CONFIGURATION
# ===============================================================================

configure_rsyslog() {
    log "INFO" "Configuring rsyslog for QRadar forwarding on RHEL family..."

    backup_file "$RSYSLOG_QRADAR_CONF"

    cp "${RESOURCE_DIR}/99-qradar.conf" "$RSYSLOG_QRADAR_CONF"
    
    # shellcheck source=../universal/99-qradar.conf
    sed -i -e "s/<QRADAR_IP>/$QRADAR_IP/g" \
        -e "s/<QRADAR_PORT>/$QRADAR_PORT/g" \
        "$RSYSLOG_QRADAR_CONF"

    chmod 644 "$RSYSLOG_QRADAR_CONF"

    # Copy rsyslog.conf
    backup_file "/etc/rsyslog.conf"
    cp "${RESOURCE_DIR}/rsyslog.conf" "/etc/rsyslog.conf"
    chmod 644 "/etc/rsyslog.conf"

    # Copy ignore_programs.json
    mkdir -p "/etc/rsyslog.d"
    backup_file "/etc/rsyslog.d/ignore_programs.json"
    cp "${RESOURCE_DIR}/ignore_programs.json" "/etc/rsyslog.d/ignore_programs.json"
    chmod 644 "/etc/rsyslog.d/ignore_programs.json"

    success "Rsyslog Universal configuration for RHEL family complete"
}

# ===============================================================================
# SERVICE MANAGEMENT
# ===============================================================================

restart_services() {
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "DRY RUN: Skipping service restarts."
        return
    fi

    log "INFO" "Restarting services for RHEL family..."
    
    # Enable services
    safe_execute "Enable auditd service" systemctl enable auditd
    if ! rsyslogd -N1 -f "$RSYSLOG_QRADAR_CONF" >> "$LOG_FILE" 2>&1; then
        error_exit "Rsyslog configuration file $RSYSLOG_QRADAR_CONF is invalid."
    fi
    success "Rsyslog configuration verified."

    safe_execute "Enable rsyslog service" systemctl enable rsyslog
    
    # Stop services
    safe_execute "Stop auditd service" systemctl stop auditd || true
    safe_execute "Stop rsyslog service" systemctl stop rsyslog || true
    
    sleep 3
    
    # Start auditd
    retry_operation "Start auditd service" systemctl start "auditd"
    
    sleep 2
    
    # Load audit rules
    load_audit_rules
    
    # Start rsyslog
    retry_operation "Start rsyslog service" systemctl start "rsyslog"
    
    success "All RHEL family services configured and started successfully"
}

load_audit_rules() {
    log "INFO" "Loading audit rules for RHEL family..."
    
    # Method 1: augenrules (RHEL 8+)
    if [[ $VERSION_MAJOR -ge 8 ]] && command_exists augenrules; then
        if safe_execute "Load rules with augenrules" augenrules --load; then
            success "Audit rules loaded with augenrules"
            return
        fi
    fi
    
    # Method 2: Direct loading with auditctl
    if safe_execute "Load rules with auditctl" auditctl -R "$AUDIT_RULES_FILE"; then
        success "Audit rules loaded with auditctl"
        return
    fi
    
    # Method 3: Line-by-line loading (fallback)
    log "INFO" "Fallback: Loading rules line by line..."
    local rules_loaded=0
    local has_e_flag=false
    while IFS= read -r line; do
        if [[ -n "$line" ]] && [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ "$line" =~ ^[[:space:]]*- ]]; then
            if [[ "$line" == "-e 2" ]]; then
                has_e_flag=true
                continue  # Apply immutable flag last
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
        success "$rules_loaded audit rules loaded line by line"
    else
        warn "No audit rules could be loaded - fallback configuration will be activated"
    fi
}

# ===============================================================================
# VALIDATION AND TESTING
# ===============================================================================

run_validation_tests() {
    log "INFO" "Running validation tests for RHEL family..."

    # Skip service tests in DRY-RUN
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "DRY-RUN: skipping service validation tests"
        return
    fi

    local services=("auditd" "rsyslog")
    for service in "${services[@]}"; do
        if detect_init && systemctl is-active --quiet "$service"; then
            success "$service service is running"
        else
            warn "$service service is not running - attempting to start..."
            safe_execute "Start $service service" systemctl start "$service"
        fi
    done
    
    # Rsyslog configuration syntax check
    if rsyslogd -N1 >> "$LOG_FILE" 2>&1; then
        success "Rsyslog configuration is valid"
    else
        warn "Rsyslog configuration validation failed (normal if service is running)"
    fi
    
    # EXECVE parser test
    if python3 - "$CONCAT_SCRIPT_PATH" <<'PYEOF'
import importlib.util, sys, pathlib, io
parser_path = sys.argv[1]
spec = importlib.util.spec_from_file_location("parser", parser_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
sample = 'type=EXECVE argc=2 a0="cat" a1="/etc/shadow" uid=0 gid=0'
print(mod.ExecveParser().parse_line(sample))
PYEOF
    then
        success "EXECVE parser test successful for RHEL family"
    else
        warn "EXECVE parser test failed"
    fi
    
    # Local syslog test
    local test_message
test_message="QRadar RHEL Universal Installer test $(date '+%Y%m%d%H%M%S')"
    logger -p user.info "$test_message"
    sleep 3
    
    if grep -q "$test_message" "$SYSLOG_FILE"; then
        success "Local syslog test successful"
    else
        warn "Local syslog test failed"
    fi
    
    # QRadar bağlantı testi
    test_qradar_connectivity
    
    # Audit functionality test
    test_audit_functionality
    
    # SELinux test
    test_selinux_configuration
}

test_qradar_connectivity() {
    log "INFO" "Testing QRadar connectivity..."
    
    if (echo > /dev/tcp/127.0.0.1/1) &>/dev/null; then
        if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$QRADAR_IP/$QRADAR_PORT" 2>/dev/null; then
            success "QRadar connectivity ($QRADAR_IP:$QRADAR_PORT) successful"
        else
            warn "Cannot connect to QRadar: $QRADAR_IP:$QRADAR_PORT"
        fi
    elif command_exists nc; then
        if timeout 5 nc -z "$QRADAR_IP" "$QRADAR_PORT" 2>/dev/null; then
            success "QRadar connectivity (with nc) successful"
        else
            warn "Cannot connect to QRadar: $QRADAR_IP:$QRADAR_PORT"
        fi
    else
        warn "Cannot test QRadar connectivity - nc tool not found"
    fi
}

test_audit_functionality() {
    log "INFO" "Testing audit functionality for RHEL family..."
    
    # Trigger a safe audit event
    cat /etc/passwd > /dev/null 2>&1 || true
    sleep 2
    
    # Check for the audit event
    if command_exists ausearch; then
        if ausearch --start today -m SYSCALL --success yes | head -n1 | grep -q "type=SYSCALL"; then
            success "Audit logging is working"
        else
            warn "Audit logging test failed"
        fi
    else
        log "INFO" "ausearch not available, skipping audit test"
    fi
}

test_selinux_configuration() {
    if [[ "$HAS_SELINUX" == true ]]; then
        log "INFO" "Testing SELinux configuration..."
        
        if command_exists getsebool; then
            local rsyslog_bool
            rsyslog_bool="$(getsebool rsyslog_can_network_connect 2>/dev/null || echo 'off')"
            if [[ "$rsyslog_bool" == *"on"* ]]; then
                success "SELinux rsyslog network boolean is active"
            else
                warn "SELinux rsyslog network boolean is disabled"
            fi
        fi
    fi
}

# ===============================================================================
# COMPREHENSIVE SETUP SUMMARY
# ===============================================================================

generate_setup_summary() {
    log "INFO" "Generating setup summary for RHEL family..."
    
    echo ""
    echo "============================================================="
    echo "       QRadar Universal RHEL Family Setup Summary"
    echo "============================================================="
    echo ""
    echo "🖥️  SYSTEM INFORMATION:"
    echo "   • Distribution: $DISTRO_NAME"
    echo "   • Version: $VERSION_MAJOR.$VERSION_MINOR"
    echo "   • Package Manager: $PACKAGE_MANAGER"
    echo "   • SELinux: $(if [[ "$HAS_SELINUX" == true ]]; then echo "Active"; else echo "Disabled"; fi)"
    echo "   • Firewalld: $(if [[ "$HAS_FIREWALLD" == true ]]; then echo "Active"; else echo "Disabled"; fi)"
    echo "   • QRadar Target: $QRADAR_IP:$QRADAR_PORT"
    echo ""
    echo "📁 CREATED FILES:"
    echo "   • Audit Rules: $AUDIT_RULES_FILE"
    echo "   • Audit Plugin: $AUDIT_SYSLOG_CONF"
    echo "   • Rsyslog Configuration: $RSYSLOG_QRADAR_CONF"
    echo "   • EXECVE Parser: $CONCAT_SCRIPT_PATH"
    echo "   • Setup Log: $LOG_FILE"
    echo "   • Backup Files: $BACKUP_DIR/"
    echo ""
    echo "🔧 SERVICE STATUS:"
    for service in auditd rsyslog; do
        if systemctl is-active --quiet "$service"; then
            echo "   ✅ $service: RUNNING"
        else
            echo "   ❌ $service: NOT RUNNING"
        fi
    done
    echo ""
    echo "🎯 FEATURES:"
    echo "   • MITRE ATT&CK compliant audit rules"
    echo "   • RHEL family version compatible configuration"
    echo "   • Automatic SELinux configuration"
    echo "   • Automatic firewalld configuration"
    echo "   • Enterprise-grade log filtering"
    echo "   • Automatic fallback mechanisms"
    echo ""
    echo "🛡️  SECURITY CONFIGURED:"
    if [[ "$HAS_SELINUX" == true ]]; then
        echo "   • SELinux booleans configured"
        echo "   • SELinux contexts set"
    fi
    if [[ "$HAS_FIREWALLD" == true ]]; then
        echo "   • Firewalld rules added"
        echo "   • QRadar port ($QRADAR_PORT/tcp) opened"
    fi
    echo ""
    echo "📝 IMPORTANT NOTES:"
    echo "   • Audit rules are not immutable (you can add -e 2 for security)"
    echo "   • Log forwarding uses the TCP protocol"
    echo "   • Only security-related logs are forwarded"
    echo "   • Configuration files are backed up in the $BACKUP_DIR directory"
    echo ""
    echo "🔍 TEST COMMANDS:"
    echo "   • Manual test: logger -p local3.info 'Test message'"
    echo "   • Audit test: sudo touch /etc/passwd"
    echo "   • Connectivity test: telnet $QRADAR_IP $QRADAR_PORT"
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
    
    success "QRadar Universal RHEL Family setup completed successfully!"
}

# ===============================================================================
# MAIN FUNCTION
# ===============================================================================

main() {
    # Create log file
    touch "$LOG_FILE" || error_exit "Cannot create log file: $LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null || true
    
    log "INFO" "============================================================="
    log "INFO" "QRadar Universal RHEL Family Log Forwarding Installer v$SCRIPT_VERSION"
    log "INFO" "Starting: $(date)"
    log "INFO" "QRadar Target: $QRADAR_IP:$QRADAR_PORT"
    log "INFO" "============================================================="
    
    # Root check
    [[ $EUID -eq 0 ]] || error_exit "This script must be run as root. Use 'sudo'."
    
    # Main installation steps
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
    log "INFO" "RHEL family installation complete: $(date)"
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
        --minimal)
            MINIMAL_RULES=true
            shift
            ;;
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

# Parameter validation
if [[ -z "$QRADAR_IP" ]] || [[ -z "$QRADAR_PORT" ]]; then
    echo "Usage: $0 <QRADAR_IP> <QRADAR_PORT> [--minimal]"
    echo "Example: $0 192.168.1.100 514 --minimal"
    exit 1
fi

# IP address format check
if ! [[ "$QRADAR_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    error_exit "Invalid IP address format: $QRADAR_IP"
fi

# Port number check
if ! [[ "$QRADAR_PORT" =~ ^[0-9]+$ ]] || [[ "$QRADAR_PORT" -lt 1 ]] || [[ "$QRADAR_PORT" -gt 65535 ]]; then
    error_exit "Invalid port number: $QRADAR_PORT (must be between 1-65535)"
fi

# Ana fonksiyonu çalıştır
main

exit 0