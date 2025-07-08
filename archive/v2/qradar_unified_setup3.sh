#!/usr/bin/env bash
#
# QRadar Unified Log Forwarding Setup Script v4.0 - Enhanced

set -euo pipefail

# =================== GLOBAL CONFIGURATION ===================
readonly SCRIPT_VERSION="4.0"
readonly LOG_FILE="/var/log/qradar_unified_setup.log"
readonly PYTHON_SCRIPT_PATH="/usr/local/bin/qradar_execve_parser.py"
readonly AUDIT_RULES_FILE="/etc/audit/rules.d/10-qradar-mitre.rules"
readonly AUDISP_PLUGIN_CONF="/etc/audisp/plugins.d/syslog.conf"
readonly RSYSLOG_SIEM_CONF="/etc/rsyslog.d/10-qradar-siem.conf"
readonly AUDIT_FACILITY="local6"  # local3'ten local6'ya değiştirildi çakışmayı önlemek için
readonly BACKUP_SUFFIX="qradar-bak-$(date +%Y%m%d-%H%M%S)"
readonly MAX_LOG_SIZE="100m"
readonly MAX_COMMAND_LENGTH=4096
readonly AUDIT_LOG_FILE="/var/log/audit/audit.log"

# Platform detection variables
DISTRO=""
DISTRO_FAMILY=""
VERSION_ID_NUM=""
PACKAGE_MANAGER=""
LOCAL_SYSLOG_FILE=""
SERVICE_MANAGER="systemctl"
AUDISP_AVAILABLE=false

# Configuration tracking arrays
declare -a MODIFIED_FILES=()
declare -a CREATED_FILES=()
declare -a BACKUP_FILES=()
declare -a INSTALLED_PACKAGES=()
declare -a ENABLED_SERVICES=()
declare -a CRON_ENTRIES=()
declare -a SYSTEMD_UNITS=()

# =================== UTILITY FUNCTIONS ===================

# Timestamped logging function
log() {
    local level="${2:-INFO}"
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $1"
    echo "$message" | tee -a "$LOG_FILE" >&2
}

# Error logging with fallback continuation
error_continue() {
    log "ERROR: $1" "ERROR"
    log "Continuing despite error..." "INFO"
}

# Warning logging
warn() {
    log "WARNING: $1" "WARN"
}

# Success logging
success() {
    log "SUCCESS: $1" "SUCCESS"
}

# Command execution with logging
execute_cmd() {
    local cmd="$1"
    local description="${2:-Executing command}"
    
    log "Executing: $cmd" "DEBUG"
    if eval "$cmd" >> "$LOG_FILE" 2>&1; then
        log "$description - SUCCESS" "DEBUG"
        return 0
    else
        local exit_code=$?
        warn "$description - FAILED (exit code: $exit_code)"
        return $exit_code
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Track file modifications
track_file_change() {
    local file="$1"
    local change_type="$2"  # created, modified, backup
    
    case "$change_type" in
        created)
            CREATED_FILES+=("$file")
            ;;
        modified)
            MODIFIED_FILES+=("$file")
            ;;
        backup)
            BACKUP_FILES+=("$file")
            ;;
    esac
}

# Track service changes
track_service_change() {
    local service="$1"
    ENABLED_SERVICES+=("$service")
}

# Track package installation
track_package_install() {
    local package="$1"
    INSTALLED_PACKAGES+=("$package")
}

# =================== PREREQUISITE CHECKS ===================

check_prerequisites() {
    log "=== QRadar Unified Log Forwarding Setup v$SCRIPT_VERSION ===" "INFO"
    log "Starting prerequisite checks..." "INFO"
    
    # Root privileges check
    if [ "$EUID" -ne 0 ]; then
        error_continue "Bu betik root yetkisiyle çalıştırılmalıdır. 'sudo' kullanın."
        exit 1
    fi
    
    # Parameters check
    if [ $# -lt 2 ]; then
        echo "Kullanım: $0 <SIEM_IP> <SIEM_PORT>" >&2
        error_continue "Gerekli parametreler eksik."
        exit 1
    fi
    
    # Validate IP address
    if ! echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        error_continue "Geçersiz SIEM IP adresi: $1"
        exit 1
    fi
    
    # Validate port number
    if ! echo "$2" | grep -Eq '^[0-9]+$' || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
        error_continue "Geçersiz SIEM port numarası: $2"
        exit 1
    fi
    
    # Initialize log file
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || error_continue "Log dizini oluşturulamadı"
    touch "$LOG_FILE" 2>/dev/null || {
        LOG_FILE="/tmp/qradar_unified_setup_$(date +%s).log"
        touch "$LOG_FILE" || exit 1
    }
    chmod 640 "$LOG_FILE" 2>/dev/null || warn "Log dosyası izinleri ayarlanamadı"
    
    success "Prerequisite checks completed"
}

# =================== PLATFORM DETECTION ===================

detect_platform() {
    log "Detecting platform and distribution..." "INFO"
    
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO="$ID"
        VERSION_ID_NUM="${VERSION_ID:-unknown}"
        
        # Determine distribution family
        case "$ID" in
            ubuntu|debian|kali|linuxmint)
                DISTRO_FAMILY="debian"
                PACKAGE_MANAGER="apt"
                LOCAL_SYSLOG_FILE="/var/log/syslog"
                ;;
            rhel|centos|almalinux|rocky|ol|oracle|fedora)
                DISTRO_FAMILY="rhel"
                PACKAGE_MANAGER=$(command -v dnf >/dev/null 2>&1 && echo "dnf" || echo "yum")
                LOCAL_SYSLOG_FILE="/var/log/messages"
                ;;
            arch|manjaro)
                DISTRO_FAMILY="arch"
                PACKAGE_MANAGER="pacman"
                LOCAL_SYSLOG_FILE="/var/log/syslog"
                ;;
            suse|opensuse*)
                DISTRO_FAMILY="suse"
                PACKAGE_MANAGER="zypper"
                LOCAL_SYSLOG_FILE="/var/log/messages"
                ;;
            *)
                warn "Bilinmeyen dağıtım: $ID"
                DISTRO_FAMILY="unknown"
                LOCAL_SYSLOG_FILE="/var/log/messages"
                ;;
        esac
    else
        error_continue "/etc/os-release dosyası bulunamadı."
        DISTRO_FAMILY="unknown"
        LOCAL_SYSLOG_FILE="/var/log/messages"
    fi
    
    # Detect service manager
    if ! command_exists systemctl; then
        SERVICE_MANAGER="service"
        log "systemd bulunamadı, service komutu kullanılacak" "INFO"
    fi
    
    log "Platform tespit edildi: $DISTRO $VERSION_ID_NUM ($DISTRO_FAMILY)" "INFO"
    success "Platform detection completed"
}

# =================== PACKAGE INSTALLATION ===================

install_packages() {
    log "Checking and installing required packages..." "INFO"
    
    # Check if essential tools already exist
    local essential_ok=true
    
    if ! command_exists auditd && ! command_exists auditctl; then
        log "Audit tools not found, will try to install..." "INFO"
        essential_ok=false
    fi
    
    if ! command_exists rsyslogd && ! command_exists rsyslog; then
        log "Rsyslog not found, will try to install..." "INFO"
        essential_ok=false
    fi
    
    if ! command_exists python3 && ! command_exists python; then
        log "Python not found, will try to install..." "INFO"
        essential_ok=false
    fi
    
    if [ "$essential_ok" = true ]; then
        log "Essential tools already installed, skipping package installation" "INFO"
        return 0
    fi
    
    # Try to install packages based on distribution
    case "$DISTRO_FAMILY" in
        debian)
            execute_cmd "apt-get update -y" "Update package cache" || warn "Paket listesi güncellenemedi"
            execute_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y auditd rsyslog python3" "Install packages" || warn "Paketler kurulamadı"
            # Try to install audisp-plugins, mark as definitively unavailable if fails
            if ! execute_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y audispd-plugins" "Install audisp plugins"; then
                warn "Audisp plugins paketi kurulamadı, alternatif yöntem kullanılacak"
                AUDISP_AVAILABLE=false
            fi
            ;;
            
        rhel)
            execute_cmd "$PACKAGE_MANAGER install -y audit rsyslog python3" "Install packages" || warn "Paketler kurulamadı"
            if ! execute_cmd "$PACKAGE_MANAGER install -y audispd-plugins" "Install audisp plugins"; then
                warn "Audisp plugins paketi kurulamadı, alternatif yöntem kullanılacak"
                AUDISP_AVAILABLE=false
            fi
            ;;
            
        *)
            warn "Paket kurulumu desteklenmeyen platform: $DISTRO_FAMILY"
            warn "Mevcut araçlarla devam ediliyor..."
            AUDISP_AVAILABLE=false
            ;;
    esac
    
    # Final audisp availability check
    check_audisp_availability_final
    
    success "Package check completed"
}

check_audisp_availability_final() {
    log "Final audisp availability check..." "INFO"
    
    # If already marked as unavailable during package install, skip check
    if [ "$AUDISP_AVAILABLE" = false ]; then
        log "Audisp already marked as unavailable, using alternative method" "INFO"
        return
    fi
    
    local audisp_paths=(
        "/sbin/audisp-syslog"
        "/usr/sbin/audisp-syslog"
        "/usr/lib/audisp/audisp-syslog"
        "/usr/libexec/audit/audisp-syslog"
    )
    
    AUDISP_AVAILABLE=false
    for path in "${audisp_paths[@]}"; do
        if [ -x "$path" ]; then
            AUDISP_AVAILABLE=true
            log "Audisp-syslog binary found at: $path" "INFO"
            return
        fi
    done
    
    log "Audisp-syslog binary not found after installation attempt" "WARN"
    log "Kesin olarak alternatif yöntem (cron tabanlı) kullanılacak" "INFO"
    AUDISP_AVAILABLE=false
}

# =================== PYTHON SCRIPT DEPLOYMENT ===================

deploy_python_script() {
    log "Deploying EXECVE argument parser script..." "INFO"
    
    # Check if Python is available
    local python_cmd=""
    if command_exists python3; then
        python_cmd="python3"
    elif command_exists python; then
        python_cmd="python"
    else
        warn "Python bulunamadı, EXECVE parser deploy edilemiyor"
        return 1
    fi
    
    if [ -f "$PYTHON_SCRIPT_PATH" ]; then
        cp "$PYTHON_SCRIPT_PATH" "${PYTHON_SCRIPT_PATH}.$BACKUP_SUFFIX" 2>/dev/null && track_file_change "${PYTHON_SCRIPT_PATH}.$BACKUP_SUFFIX" "backup"
    fi
    
    # Create directory if not exists
    mkdir -p "$(dirname "$PYTHON_SCRIPT_PATH")" || {
        warn "Python script dizini oluşturulamadı"
        return 1
    }
    
    cat > "$PYTHON_SCRIPT_PATH" << 'PYTHON_SCRIPT_EOF'
#!/usr/bin/env python3
"""
QRadar EXECVE Argument Parser v4.0
Enhanced for better rsyslog integration
"""

import sys
import re
import json
import time
import signal
from datetime import datetime

class ExecveParser:
    def __init__(self):
        self.execve_pattern = re.compile(r'type=EXECVE', re.IGNORECASE)
        self.arg_pattern = re.compile(r'a(\d+)="([^"]*)"', re.IGNORECASE)
        self.max_command_length = 4096
        self.buffer = []
        
        # Handle signals gracefully
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        sys.exit(0)
    
    def parse_execve_line(self, line):
        """Parse EXECVE line and reconstruct command"""
        if not self.execve_pattern.search(line):
            return line
            
        try:
            # Extract all arguments
            args = {}
            for match in self.arg_pattern.finditer(line):
                arg_num = int(match.group(1))
                arg_value = match.group(2)
                if arg_value:  # Skip empty arguments
                    args[arg_num] = arg_value
            
            if not args:
                return line
                
            # Reconstruct command from arguments
            command_parts = []
            for i in sorted(args.keys()):
                command_parts.append(args[i])
            
            full_command = ' '.join(command_parts)
            if len(full_command) > self.max_command_length:
                full_command = full_command[:self.max_command_length] + '...'
            
            # Remove all existing aX= fields to reduce log size
            cleaned_line = self.arg_pattern.sub('', line).strip()
            
            # Add reconstructed command at the end
            enhanced_line = f"{cleaned_line} cmd=\"{full_command}\""
            
            return enhanced_line
            
        except Exception as e:
            sys.stderr.write(f"EXECVE_PARSER_ERROR: {str(e)}\n")
            sys.stderr.flush()
            return line
    
    def run(self):
        """Main processing loop"""
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    break
                    
                # Process line
                processed_line = self.parse_execve_line(line.rstrip())
                
                # Output processed line
                sys.stdout.write(processed_line + '\n')
                sys.stdout.flush()
                
        except Exception as e:
            sys.stderr.write(f"EXECVE_PARSER_FATAL: {str(e)}\n")
            sys.stderr.flush()

def main():
    parser = ExecveParser()
    parser.run()

if __name__ == '__main__':
    main()
PYTHON_SCRIPT_EOF
    
    # Set shebang based on available Python
    sed -i "1s|.*|#!$(which $python_cmd)|" "$PYTHON_SCRIPT_PATH" || warn "Shebang güncellenemedi"
    
    chmod 755 "$PYTHON_SCRIPT_PATH" || error_continue "Python script izinleri ayarlanamadı"
    chown root:root "$PYTHON_SCRIPT_PATH" 2>/dev/null || warn "Python script sahipliği ayarlanamadı"
    
    track_file_change "$PYTHON_SCRIPT_PATH" "created"
    
    # Test the script
    if echo 'type=EXECVE a0="ls" a1="-la"' | "$PYTHON_SCRIPT_PATH" | grep -q 'cmd="ls -la"'; then
        success "Python EXECVE parser deployed and tested successfully"
    else
        warn "Python EXECVE parser test başarısız, basit log forwarding kullanılacak"
    fi
}

# =================== AUDIT CONFIGURATION ===================

configure_auditd() {
    log "Configuring auditd..." "INFO"
    
    # Check if auditd is available
    if ! command_exists auditctl && ! [ -f /etc/audit/auditd.conf ]; then
        warn "Audit sistem bulunamadı, audit yapılandırması atlanıyor"
        return 0
    fi
    
    # Create rules directory
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")" || {
        warn "Audit rules dizini oluşturulamadı"
        return 1
    }
    
    if [ -f "$AUDIT_RULES_FILE" ]; then
        cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.$BACKUP_SUFFIX" 2>/dev/null && track_file_change "${AUDIT_RULES_FILE}.$BACKUP_SUFFIX" "backup"
    fi
    
    # Create optimized audit rules (reduced to minimize noise)
    cat > "$AUDIT_RULES_FILE" << 'AUDIT_RULES_EOF'
# QRadar MITRE ATT&CK Aligned Audit Rules v4.0 - Optimized
# Reduced ruleset to minimize noise while maintaining security visibility

# Delete all existing rules and set configuration
-D
-b 8192
-f 1
--backlog_wait_time 60000

# Rate limit to prevent audit flooding
-r 100

##########################################
# Critical Security Events Only
##########################################

# Authentication and Authorization
-w /etc/passwd -p wa -k user_modification
-w /etc/shadow -p wa -k user_modification
-w /etc/group -p wa -k group_modification
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/sudoers.d/ -p wa -k sudoers_modification

# SSH Access
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Privilege Escalation Monitoring
-a always,exit -F arch=b64 -S setuid -F a0=0 -F exe=/usr/bin/sudo -k privilege_escalation
-a always,exit -F arch=b64 -S setuid -F a0=0 -F exe=/usr/bin/su -k privilege_escalation

# Critical Command Execution (root only)
-a always,exit -F arch=b64 -S execve -F euid=0 -F key=root_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -F key=root_commands

# System Integrity
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules

# Suspicious Activity
-w /tmp -p x -F auid!=4294967295 -k suspicious_execution
-w /var/tmp -p x -F auid!=4294967295 -k suspicious_execution

# Critical Service Management
-w /usr/bin/systemctl -p x -k service_management
-w /sbin/service -p x -k service_management

# Network Configuration Changes
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/network/ -p wa -k network_config

# Cron Jobs (persistence mechanism)
-w /etc/crontab -p wa -k cron_modification
-w /etc/cron.d/ -p wa -k cron_modification
-w /var/spool/cron/ -p wa -k cron_modification

# File Integrity
-w /etc/ld.so.conf -p wa -k libpath
-w /etc/ld.so.conf.d/ -p wa -k libpath
AUDIT_RULES_EOF

    chmod 640 "$AUDIT_RULES_FILE" || warn "Audit rules dosyası izinleri ayarlanamadı"
    track_file_change "$AUDIT_RULES_FILE" "created"
    
    # Configure audit logging
    configure_audit_logging
    
    # Configure log forwarding method based on audisp availability
    if [ "$AUDISP_AVAILABLE" = true ]; then
        log "Audisp mevcut, plugin yapılandırılıyor..." "INFO"
        if ! configure_audisp_plugin; then
            warn "Audisp plugin yapılandırması başarısız, alternatif yönteme geçiliyor"
            AUDISP_AVAILABLE=false
            configure_audit_direct_logging
        fi
    else
        log "Audisp mevcut değil veya yapılandırılamıyor, kesin olarak alternatif yöntem kullanılıyor" "INFO"
        configure_audit_direct_logging
    fi
    
    # Load audit rules
    load_audit_rules
    
    success "Auditd configuration completed"
}

configure_audit_logging() {
    log "Configuring audit logging parameters..." "INFO"
    
    local audit_conf="/etc/audit/auditd.conf"
    if [ -f "$audit_conf" ]; then
        cp "$audit_conf" "${audit_conf}.$BACKUP_SUFFIX" 2>/dev/null && track_file_change "${audit_conf}.$BACKUP_SUFFIX" "backup"
        
        # Optimize audit logging
        sed -i 's/^num_logs.*/num_logs = 5/' "$audit_conf" 2>/dev/null
        sed -i 's/^max_log_file.*/max_log_file = 50/' "$audit_conf" 2>/dev/null
        sed -i 's/^max_log_file_action.*/max_log_file_action = rotate/' "$audit_conf" 2>/dev/null
        sed -i 's/^space_left_action.*/space_left_action = syslog/' "$audit_conf" 2>/dev/null
        sed -i 's/^admin_space_left_action.*/admin_space_left_action = suspend/' "$audit_conf" 2>/dev/null
        sed -i 's/^disk_full_action.*/disk_full_action = suspend/' "$audit_conf" 2>/dev/null
        sed -i 's/^disk_error_action.*/disk_error_action = suspend/' "$audit_conf" 2>/dev/null
        
        # Enable syslog by default
        if ! grep -q "^write_logs" "$audit_conf"; then
            echo "write_logs = yes" >> "$audit_conf"
        fi
        
        track_file_change "$audit_conf" "modified"
    fi
}

configure_audit_direct_logging() {
    log "Configuring direct audit to rsyslog forwarding (audisp alternative)..." "INFO"
    
    # Create a more robust script to read audit log and forward to rsyslog
    local audit_forwarder="/usr/local/bin/audit_to_rsyslog.sh"
    
    cat > "$audit_forwarder" << 'EOF'
#!/bin/bash
# Direct audit log forwarder to rsyslog - Alternative to audisp
# This script reads audit.log and forwards security events to rsyslog

AUDIT_LOG="/var/log/audit/audit.log"
LAST_POS_FILE="/var/run/audit_forwarder.pos"
LOCK_FILE="/var/run/audit_forwarder.lock"
MAX_LINES_PER_RUN=1000

# Use flock to prevent multiple instances
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    exit 0
fi

# Ensure position file exists
touch "$LAST_POS_FILE" 2>/dev/null || LAST_POS_FILE="/tmp/audit_forwarder.pos"

# Get last position
if [ -f "$LAST_POS_FILE" ]; then
    LAST_POS=$(cat "$LAST_POS_FILE" 2>/dev/null || echo 0)
else
    LAST_POS=0
fi

# Validate last position is numeric
if ! [[ "$LAST_POS" =~ ^[0-9]+$ ]]; then
    LAST_POS=0
fi

# Check if audit log exists
if [ ! -f "$AUDIT_LOG" ]; then
    exit 0
fi

# Check current file size
CURRENT_SIZE=$(stat -c%s "$AUDIT_LOG" 2>/dev/null || echo 0)

# If file is smaller than last position, it was rotated
if [ "$CURRENT_SIZE" -lt "$LAST_POS" ]; then
    LAST_POS=0
fi

# Read new lines and send to syslog
if [ "$CURRENT_SIZE" -gt "$LAST_POS" ]; then
    # Calculate bytes to read
    BYTES_TO_READ=$((CURRENT_SIZE - LAST_POS))
    
    # Read and process new lines
    tail -c +"$((LAST_POS + 1))" "$AUDIT_LOG" | head -n "$MAX_LINES_PER_RUN" | while IFS= read -r line; do
        # Filter for security-relevant events only
        if echo "$line" | grep -qE '(type=USER_|type=EXECVE|type=SYSCALL.*exe=|type=PROCTITLE|key=|type=CRYPTO_KEY|uid=0)' && \
           ! echo "$line" | grep -qE '(type=CRYPTO_KEY_USER|type=SERVICE_|type=USER_ACCT.*pam_unix)'; then
            # Send to rsyslog with local6 facility
            logger -p local6.info -t audit -- "$line"
        fi
    done
    
    # Update position (max of current size or last pos + bytes processed)
    NEW_POS="$CURRENT_SIZE"
    echo "$NEW_POS" > "$LAST_POS_FILE"
fi

# Clean up lock
flock -u 200
EOF
    
    chmod 755 "$audit_forwarder" || warn "Audit forwarder script izinleri ayarlanamadı"
    track_file_change "$audit_forwarder" "created"
    
    log "Setting up automated execution for audit forwarder..." "INFO"
    
    # Try systemd timer first (more reliable than cron)
    if [ "$SERVICE_MANAGER" = "systemctl" ] && command_exists systemctl; then
        # Create systemd service
        cat > "/etc/systemd/system/audit-to-rsyslog.service" << EOF
[Unit]
Description=Forward audit logs to rsyslog
After=auditd.service rsyslog.service

[Service]
Type=oneshot
ExecStart=$audit_forwarder
StandardOutput=journal
StandardError=journal
EOF
        track_file_change "/etc/systemd/system/audit-to-rsyslog.service" "created"

        # Create systemd timer (every 30 seconds)
        cat > "/etc/systemd/system/audit-to-rsyslog.timer" << EOF
[Unit]
Description=Run audit to rsyslog forwarder every 30 seconds
After=auditd.service rsyslog.service

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF
        track_file_change "/etc/systemd/system/audit-to-rsyslog.timer" "created"

        # Enable and start timer
        execute_cmd "systemctl daemon-reload" "Reload systemd" || warn "systemd daemon-reload başarısız"
        execute_cmd "systemctl enable audit-to-rsyslog.timer" "Enable audit forwarder timer" || warn "Timer enable edilemedi"
        execute_cmd "systemctl start audit-to-rsyslog.timer" "Start audit forwarder timer" || warn "Timer başlatılamadı"
        
        log "Systemd timer configured for audit forwarding" "INFO"
    else
        # Fallback to cron
        log "Using cron for audit forwarding (systemd not available)" "INFO"
        
        # Add to cron for every minute execution
        local cron_entry="* * * * * $audit_forwarder >/dev/null 2>&1"
        
        # Check if cron entry already exists
        if ! crontab -l 2>/dev/null | grep -qF "$audit_forwarder"; then
            (crontab -l 2>/dev/null || echo ""; echo "$cron_entry") | crontab - || warn "Cron entry eklenemedi"
        fi
        
        log "Cron job configured for audit forwarding" "INFO"
    fi
    
    # Test the forwarder script immediately
    execute_cmd "$audit_forwarder" "Test audit forwarder" || warn "Audit forwarder test execution failed"
    
    log "Direct audit forwarding (audisp alternative) configured successfully" "INFO"
}

configure_audisp_plugin() {
    log "Configuring audisp-syslog plugin..." "INFO"
    
    # Find audisp-syslog binary
    local audisp_binary=""
    local possible_paths=(
        "/sbin/audisp-syslog"
        "/usr/sbin/audisp-syslog"
        "/usr/lib/audisp/audisp-syslog"
        "/usr/libexec/audit/audisp-syslog"
    )
    
    for path in "${possible_paths[@]}"; do
        if [ -x "$path" ]; then
            audisp_binary="$path"
            break
        fi
    done
    
    if [ -z "$audisp_binary" ]; then
        warn "audisp-syslog binary bulunamadı"
        return 1
    fi
    
    mkdir -p "$(dirname "$AUDISP_PLUGIN_CONF")" || warn "Audisp config dizini oluşturulamadı"
    
    cat > "$AUDISP_PLUGIN_CONF" << EOF
active = yes
direction = out
path = $audisp_binary
type = always
args = LOG_LOCAL6
format = string
EOF
    
    chmod 640 "$AUDISP_PLUGIN_CONF" 2>/dev/null || warn "Audisp config izinleri ayarlanamadı"
    track_file_change "$AUDISP_PLUGIN_CONF" "created"
    log "Audisp-syslog plugin configured" "INFO"
    return 0
}

load_audit_rules() {
    log "Loading audit rules..." "INFO"
    
    # Start/restart auditd
    if [ "$SERVICE_MANAGER" = "systemctl" ]; then
        execute_cmd "systemctl enable auditd" "Enable auditd" || warn "auditd enable edilemedi"
        execute_cmd "systemctl restart auditd" "Restart auditd" || {
            execute_cmd "service auditd restart" "Restart auditd (fallback)" || warn "auditd yeniden başlatılamadı"
        }
    else
        execute_cmd "service auditd restart" "Restart auditd" || warn "auditd yeniden başlatılamadı"
    fi
    
    sleep 3
    
    # Load rules
    if command_exists augenrules; then
        execute_cmd "augenrules --load" "Load audit rules with augenrules" || warn "augenrules ile yükleme başarısız"
    elif command_exists auditctl; then
        execute_cmd "auditctl -R '$AUDIT_RULES_FILE'" "Load audit rules with auditctl" || warn "auditctl ile yükleme başarısız"
    fi
    
    # Verify rules loaded
    if command_exists auditctl; then
        local rule_count
        rule_count=$(auditctl -l 2>/dev/null | wc -l)
        if [ "$rule_count" -gt 0 ]; then
            log "Audit rules loaded: $rule_count rules active" "INFO"
        else
            warn "Audit kuralları yüklenmemiş görünüyor"
        fi
    fi
}

# =================== RSYSLOG CONFIGURATION ===================

configure_rsyslog() {
    log "Configuring rsyslog for QRadar SIEM forwarding..." "INFO"
    
    local siem_ip="$1"
    local siem_port="$2"
    
    # Check if rsyslog is available
    if ! command_exists rsyslogd; then
        error_continue "rsyslog bulunamadı, log forwarding yapılandırılamıyor"
        return 1
    fi
    
    if [ -f "$RSYSLOG_SIEM_CONF" ]; then
        cp "$RSYSLOG_SIEM_CONF" "${RSYSLOG_SIEM_CONF}.$BACKUP_SUFFIX" 2>/dev/null && track_file_change "${RSYSLOG_SIEM_CONF}.$BACKUP_SUFFIX" "backup"
    fi
    
    # Check if Python script is available for EXECVE parsing
    local use_python_parser=false
    if [ -x "$PYTHON_SCRIPT_PATH" ] && command_exists python3 || command_exists python; then
        use_python_parser=true
    fi
    
    # Create optimized rsyslog configuration
    cat > "$RSYSLOG_SIEM_CONF" << EOF
# QRadar SIEM Forwarding Configuration v4.0
# Optimized for minimal noise and maximum security visibility

# Load required modules
module(load="imudp")
module(load="imtcp")
module(load="imklog") # Kernel log processing
module(load="immark") # Mark messages
EOF

    # Add omprog module only if Python parser is available
    if [ "$use_python_parser" = true ]; then
        echo 'module(load="omprog")' >> "$RSYSLOG_SIEM_CONF"
    fi

    cat >> "$RSYSLOG_SIEM_CONF" << EOF

# Global configuration
\$WorkDirectory /var/spool/rsyslog
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# Queue configuration for reliable delivery
\$ActionQueueType LinkedList
\$ActionQueueFileName qradar_fwd
\$ActionQueueMaxDiskSpace 1g
\$ActionQueueSaveOnShutdown on
\$ActionQueueSize 50000
\$ActionQueueDiscardMark 45000
\$ActionQueueDiscardSeverity 0
\$ActionResumeRetryCount -1
\$ActionResumeInterval 30

# Custom template for QRadar
template(name="QRadarFormat" type="string"
    string="<%PRI%>%TIMESTAMP% %HOSTNAME% %APP-NAME%[%PROCID%]: %MSG%\n")

# Enhanced filtering to reduce noise
# Drop all kernel messages except critical ones
if \$syslogfacility-text == 'kern' and \$syslogseverity > 3 then stop

# Drop debug and info messages from most facilities
if \$syslogseverity >= 6 then stop

# Drop noisy daemon messages
if \$programname == 'systemd' and \$msg contains 'Started Session' then stop
if \$programname == 'systemd' and \$msg contains 'Removed slice' then stop
if \$programname == 'systemd' and \$msg contains 'Created slice' then stop
if \$programname == 'systemd-logind' and \$msg contains 'New session' then stop
if \$programname == 'systemd-logind' and \$msg contains 'Removed session' then stop
if \$programname contains 'dhclient' then stop
if \$programname == 'dbus' then stop
if \$programname == 'dbus-daemon' then stop
if \$programname == 'NetworkManager' and \$syslogseverity >= 5 then stop

# Process audit logs from local6 facility (our audit facility)
if \$syslogfacility-text == '$AUDIT_FACILITY' then {
    # Filter for security-relevant events only
    if (
        \$msg contains "type=USER_" or
        \$msg contains "type=EXECVE" or
        \$msg contains "type=SYSCALL" or
        \$msg contains "key=" or
        \$msg contains "type=PROCTITLE" or
        \$msg contains "type=PATH" or
        \$msg contains "type=CWD" or
        \$msg contains "type=SOCKADDR"
    ) then {
EOF

    # Add Python parser action if available
    if [ "$use_python_parser" = true ]; then
        cat >> "$RSYSLOG_SIEM_CONF" << EOF
        # Process EXECVE messages with Python parser
        if \$msg contains "type=EXECVE" then {
            action(
                type="omprog"
                binary="$PYTHON_SCRIPT_PATH"
                template="RSYSLOG_TraditionalFileFormat"
            )
        }
EOF
    fi

    cat >> "$RSYSLOG_SIEM_CONF" << EOF
        # Forward to QRadar
        action(
            type="omfwd"
            target="$siem_ip"
            port="$siem_port"
            protocol="tcp"
            template="QRadarFormat"
            queue.filename="qradar_audit"
            queue.maxdiskspace="500m"
            queue.saveonshutdown="on"
            action.resumeRetryCount="-1"
            action.resumeInterval="30"
        )
    }
    stop
}

# Forward authentication and security events
if (
    \$programname == 'sshd' or
    \$programname == 'sudo' or
    \$programname == 'su' or
    \$programname == 'login' or
    \$programname == 'gdm' or
    \$programname == 'kdm' or
    \$programname == 'lightdm' or
    \$programname contains 'pam' or
    \$msg contains "authentication failure" or
    \$msg contains "session opened" or
    \$msg contains "session closed" or
    \$msg contains "Accepted password" or
    \$msg contains "Accepted publickey" or
    \$msg contains "Failed password" or
    \$msg contains "Invalid user" or
    \$msg contains "COMMAND=" or
    \$msg contains "sudo:" or
    \$msg contains "su[" or
    \$msg contains "ROOT LOGIN"
) then {
    action(
        type="omfwd"
        target="$siem_ip"
        port="$siem_port"
        protocol="tcp"
        template="QRadarFormat"
        queue.filename="qradar_auth"
        queue.maxdiskspace="200m"
        queue.saveonshutdown="on"
    )
}

# Forward critical system events
if (
    \$syslogseverity <= 3 or
    \$msg contains "kernel:" and \$syslogseverity <= 4 or
    \$msg contains "error" or
    \$msg contains "fail" or
    \$msg contains "alert" or
    \$msg contains "critical" or
    \$msg contains "emergency" or
    \$msg contains "panic"
) and not (
    \$programname == 'systemd' or
    \$programname contains 'journal'
) then {
    action(
        type="omfwd"
        target="$siem_ip"
        port="$siem_port"
        protocol="tcp"
        template="QRadarFormat"
        queue.filename="qradar_critical"
        queue.maxdiskspace="100m"
        queue.saveonshutdown="on"
    )
}

# Log local copy for debugging (optional, can be commented out)
#*.* /var/log/qradar-forward.log

# Stop processing after forwarding
& stop
EOF

    chmod 644 "$RSYSLOG_SIEM_CONF" || warn "rsyslog config izinleri ayarlanamadı"
    track_file_change "$RSYSLOG_SIEM_CONF" "created"
    
    # Validate configuration
    validate_rsyslog_config
    
    # Restart rsyslog
    restart_rsyslog
    
    success "Rsyslog configuration completed"
}

validate_rsyslog_config() {
    log "Validating rsyslog configuration..." "INFO"
    
    if command_exists rsyslogd; then
        local validation_output
        validation_output=$(rsyslogd -N1 2>&1)
        local validation_result=$?
        
        if [ $validation_result -eq 0 ]; then
            log "Rsyslog configuration validation passed" "INFO"
        else
            warn "Rsyslog configuration validation warnings:"
            echo "$validation_output" >> "$LOG_FILE"
        fi
    fi
}

restart_rsyslog() {
    log "Restarting rsyslog service..." "INFO"
    
    if [ "$SERVICE_MANAGER" = "systemctl" ]; then
        execute_cmd "systemctl enable rsyslog" "Enable rsyslog" || warn "rsyslog enable edilemedi"
        execute_cmd "systemctl restart rsyslog" "Restart rsyslog" || {
            execute_cmd "service rsyslog restart" "Restart rsyslog (fallback)" || error_continue "rsyslog yeniden başlatılamadı"
        }
    else
        execute_cmd "service rsyslog restart" "Restart rsyslog" || error_continue "rsyslog yeniden başlatılamadı"
    fi
    
    sleep 3
    
    # Verify rsyslog is running
    if pgrep rsyslogd >/dev/null 2>&1; then
        log "rsyslog service is running" "INFO"
    else
        error_continue "rsyslog service is not running"
    fi
}

# =================== TESTING ===================

test_configuration() {
    local siem_ip="$1"
    local siem_port="$2"
    
    log "Testing configuration..." "INFO"
    
    # Test network connectivity
    log "Testing network connectivity to $siem_ip:$siem_port..." "INFO"
    if command_exists nc; then
        if timeout 5 nc -z "$siem_ip" "$siem_port" 2>/dev/null; then
            success "Network connectivity test passed"
        else
            warn "Network connectivity test failed - check firewall rules"
        fi
    elif command_exists telnet; then
        if timeout 5 bash -c "echo | telnet $siem_ip $siem_port" 2>&1 | grep -q "Connected"; then
            success "Network connectivity test passed"
        else
            warn "Network connectivity test failed - check firewall rules"
        fi
    else
        warn "No network testing tools available"
    fi
    
    # Generate test events
    log "Generating test events..." "INFO"
    
    # Test audit event
    logger -p ${AUDIT_FACILITY}.info "TEST: QRadar audit test from $(hostname) at $(date)"
    
    # Test auth event
    logger -p auth.info "TEST: QRadar auth test - sudo command execution test"
    
    # Test critical event
    logger -p syslog.err "TEST: QRadar critical test - simulated error condition"
    
    log "Test events generated. Check QRadar console for incoming events." "INFO"
}

# =================== MAIN EXECUTION ===================

generate_final_report() {
    local siem_ip="$1"
    local siem_port="$2"
    
    # Create a detailed report file
    local report_file="/root/qradar_setup_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "========================================================================="
        echo "           QRadar Unified Log Forwarding Setup Report"
        echo "========================================================================="
        echo ""
        echo "Kurulum Tarihi: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Script Versiyonu: $SCRIPT_VERSION"
        echo "Sunucu Hostname: $(hostname)"
        echo "İşletim Sistemi: $DISTRO $VERSION_ID_NUM ($DISTRO_FAMILY)"
        echo ""
        echo "========================================================================="
        echo "                          HEDEF SIEM BİLGİLERİ"
        echo "========================================================================="
        echo "QRadar IP Adresi: $siem_ip"
        echo "QRadar Port: $siem_port"
        echo "Kullanılan Facility: $AUDIT_FACILITY"
        echo ""
        echo "========================================================================="
        echo "                       KURULUM YÖNTEMİ VE DURUMU"
        echo "========================================================================="
        
        if [ "$AUDISP_AVAILABLE" = true ]; then
            echo "Log İletim Yöntemi: Audisp-syslog Plugin (Standart)"
            echo "Durum: Audisp başarıyla yapılandırıldı"
        else
            echo "Log İletim Yöntemi: Doğrudan Audit->Rsyslog (Alternatif)"
            echo "Durum: Audisp bulunamadığı için alternatif yöntem kullanıldı"
            echo ""
            echo "Alternatif Yöntem Detayları:"
            if [ "$SERVICE_MANAGER" = "systemctl" ]; then
                echo "  - Systemd timer ile her 30 saniyede bir audit logları kontrol edilecek"
                echo "  - Timer Durumu: $(systemctl is-active audit-to-rsyslog.timer 2>/dev/null || echo "Bilinmiyor")"
            else
                echo "  - Cron job ile her dakika audit logları kontrol edilecek"
            fi
            echo "  - Script Konumu: /usr/local/bin/audit_to_rsyslog.sh"
        fi
        
        echo ""
        echo "========================================================================="
        echo "                        YAPILANDIRILAN SERVİSLER"
        echo "========================================================================="
        
        # Service status
        for service in auditd rsyslog; do
            if [ "$SERVICE_MANAGER" = "systemctl" ]; then
                local status=$(systemctl is-active "$service" 2>/dev/null || echo "Bilinmiyor")
                local enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "Bilinmiyor")
                echo "$service:"
                echo "  - Durum: $status"
                echo "  - Otomatik Başlatma: $enabled"
            else
                if service "$service" status >/dev/null 2>&1; then
                    echo "$service: Çalışıyor"
                else
                    echo "$service: Çalışmıyor"
                fi
            fi
        done
        
        if [ "$AUDISP_AVAILABLE" = false ] && [ "$SERVICE_MANAGER" = "systemctl" ]; then
            echo ""
            echo "audit-to-rsyslog (Alternatif yöntem):"
            echo "  - Timer Durumu: $(systemctl is-active audit-to-rsyslog.timer 2>/dev/null || echo "Bilinmiyor")"
            echo "  - Son Çalışma: $(systemctl status audit-to-rsyslog.service 2>/dev/null | grep "Active:" | sed 's/.*;//' || echo "Bilinmiyor")"
        fi
        
        echo ""
        echo "========================================================================="
        echo "                     OLUŞTURULAN/DEĞİŞTİRİLEN DOSYALAR"
        echo "========================================================================="
        
        echo "Yeni Oluşturulan Dosyalar:"
        if [ ${#CREATED_FILES[@]} -eq 0 ]; then
            echo "  - Yeni dosya oluşturulmadı"
        else
            for file in "${CREATED_FILES[@]}"; do
                echo "  - $file"
            done
        fi
        
        echo ""
        echo "Değiştirilen Konfigürasyon Dosyaları:"
        local config_files=(
            "$AUDIT_RULES_FILE"
            "$RSYSLOG_SIEM_CONF"
            "$AUDISP_PLUGIN_CONF"
            "/etc/audit/auditd.conf"
        )
        
        for file in "${config_files[@]}"; do
            if [ -f "$file" ]; then
                echo "  - $file"
                if [ -f "${file}.$BACKUP_SUFFIX" ]; then
                    echo "    (Yedek: ${file}.$BACKUP_SUFFIX)"
                fi
            fi
        done
        
        if [ "$AUDISP_AVAILABLE" = false ]; then
            echo "  - /usr/local/bin/audit_to_rsyslog.sh (Alternatif forwarder)"
            if [ "$SERVICE_MANAGER" = "systemctl" ]; then
                echo "  - /etc/systemd/system/audit-to-rsyslog.service"
                echo "  - /etc/systemd/system/audit-to-rsyslog.timer"
            fi
        fi
        
        if [ -x "$PYTHON_SCRIPT_PATH" ]; then
            echo "  - $PYTHON_SCRIPT_PATH (EXECVE parser)"
        fi
        
        echo ""
        echo "========================================================================="
        echo "                          AUDIT KURALLARI"
        echo "========================================================================="
        
        if command_exists auditctl; then
            local rule_count=$(auditctl -l 2>/dev/null | wc -l)
            echo "Toplam Aktif Kural Sayısı: $rule_count"
            echo ""
            echo "Kural Kategorileri:"
            echo "  - Kimlik doğrulama ve yetkilendirme takibi"
            echo "  - Kritik dosya değişiklikleri (passwd, shadow, sudoers)"
            echo "  - Root komut çalıştırma takibi"
            echo "  - Şüpheli dizinlerde çalıştırma (/tmp, /var/tmp)"
            echo "  - Sistem servisleri yönetimi"
            echo "  - Ağ yapılandırma değişiklikleri"
            echo "  - Cron job değişiklikleri"
        else
            echo "Audit kuralları yüklenemedi veya auditctl mevcut değil"
        fi
        
        echo ""
        echo "========================================================================="
        echo "                         LOG FİLTRELEME"
        echo "========================================================================="
        echo "Engellenen Gereksiz Loglar:"
        echo "  - Kernel debug/info mesajları (facility=kern, severity>3)"
        echo "  - Tüm debug ve info seviyesi loglar (severity>=6)"
        echo "  - Systemd session logları (Started Session, Removed slice)"
        echo "  - NetworkManager bilgi mesajları"
        echo "  - dbus, dhclient mesajları"
        echo ""
        echo "İletilen Önemli Loglar:"
        echo "  - Kimlik doğrulama olayları (SSH, sudo, su)"
        echo "  - Audit güvenlik olayları"
        echo "  - Kritik sistem hataları (severity<=3)"
        echo "  - Güvenlik anahtar kelimeleri içeren loglar"
        
        echo ""
        echo "========================================================================="
        echo "                      TEST VE DOĞRULAMA KOMUTLARI"
        echo "========================================================================="
        echo "1. Log iletimini test etmek için:"
        echo "   logger -p ${AUDIT_FACILITY}.info 'QRadar test message from $(hostname)'"
        echo ""
        echo "2. Audit olaylarını izlemek için:"
        echo "   tail -f $AUDIT_LOG_FILE | grep -E '(USER_|EXECVE|key=)'"
        echo ""
        echo "3. Rsyslog durumunu kontrol etmek için:"
        echo "   journalctl -u rsyslog -f"
        echo ""
        echo "4. Network trafiğini izlemek için:"
        echo "   tcpdump -i any host $siem_ip and port $siem_port -nn"
        echo ""
        
        if [ "$AUDISP_AVAILABLE" = false ]; then
            echo "5. Alternatif forwarder'ı manuel test etmek için:"
            echo "   /usr/local/bin/audit_to_rsyslog.sh"
            echo ""
            if [ "$SERVICE_MANAGER" = "systemctl" ]; then
                echo "6. Alternatif forwarder timer durumu:"
                echo "   systemctl status audit-to-rsyslog.timer"
            fi
        fi
        
        echo ""
        echo "========================================================================="
        echo "                          SORUN GİDERME"
        echo "========================================================================="
        echo "Log iletimi çalışmıyorsa kontrol edilecekler:"
        echo ""
        echo "1. Firewall kuralları:"
        echo "   - Giden $siem_port/tcp trafiğine izin verilmeli"
        echo "   - iptables -L OUTPUT -n | grep $siem_port"
        echo ""
        echo "2. SELinux (RHEL/CentOS):"
        echo "   - getenforce"
        echo "   - setsebool -P nis_enabled 1"
        echo ""
        echo "3. Servis logları:"
        echo "   - journalctl -xe"
        echo "   - tail -f /var/log/messages"
        echo "   - tail -f $LOG_FILE"
        echo ""
        echo "4. Audit daemon durumu:"
        echo "   - auditctl -s"
        echo "   - ausearch -m USER_LOGIN -ts recent"
        
        echo ""
        echo "========================================================================="
        echo "                            GERİ ALMA"
        echo "========================================================================="
        echo "Yapılandırmayı geri almak için:"
        echo ""
        echo "1. Yedek dosyaları geri yükleyin:"
        for file in "${BACKUP_FILES[@]}"; do
            if [ -f "$file" ]; then
                echo "   mv $file ${file%.$BACKUP_SUFFIX}"
            fi
        done
        echo ""
        echo "2. Oluşturulan dosyaları silin:"
        echo "   rm -f $RSYSLOG_SIEM_CONF"
        echo "   rm -f $PYTHON_SCRIPT_PATH"
        if [ "$AUDISP_AVAILABLE" = false ]; then
            echo "   rm -f /usr/local/bin/audit_to_rsyslog.sh"
            if [ "$SERVICE_MANAGER" = "systemctl" ]; then
                echo "   systemctl disable --now audit-to-rsyslog.timer"
                echo "   rm -f /etc/systemd/system/audit-to-rsyslog.*"
            else
                echo "   crontab -l | grep -v audit_to_rsyslog | crontab -"
            fi
        fi
        echo ""
        echo "3. Servisleri yeniden başlatın:"
        echo "   systemctl restart auditd rsyslog"
        
        echo ""
        echo "========================================================================="
        echo "                              ÖZET"
        echo "========================================================================="
        echo "Kurulum Durumu: BAŞARILI"
        echo "Log İletim Yöntemi: $([ "$AUDISP_AVAILABLE" = true ] && echo "Audisp Plugin" || echo "Alternatif Cron/Timer")"
        echo "Detaylı Log: $LOG_FILE"
        echo "Bu Rapor: $report_file"
        echo ""
        echo "QRadar SIEM sunucunuz $siem_ip:$siem_port adresinde logları almaya başlamış olmalıdır."
        echo ""
        echo "========================================================================="
        
    } | tee "$report_file"
    
    log "Detailed report saved to: $report_file" "INFO"
    
    # Also display a short summary to console
    echo ""
    echo "KURULUM TAMAMLANDI!"
    echo "==================="
    echo "Detaylı rapor: $report_file"
    echo "Log dosyası: $LOG_FILE"
}

main() {
    check_prerequisites "$@"
    
    local siem_ip="$1"
    local siem_port="$2"
    
    detect_platform
    install_packages
    deploy_python_script
    configure_auditd
    configure_rsyslog "$siem_ip" "$siem_port"
    test_configuration "$siem_ip" "$siem_port"
    
    # Generate comprehensive final report
    generate_final_report "$siem_ip" "$siem_port"
}

# Run main function
main "$@"
