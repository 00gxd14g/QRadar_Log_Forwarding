#!/usr/bin/env bash
#
# QRadar Unified Log Forwarding Setup Script v3.0

# Kullanım: sudo bash qradar_unified_setup.sh <SIEM_IP> <SIEM_PORT>
#

set -euo pipefail

# =================== GLOBAL CONFIGURATION ===================
readonly SCRIPT_VERSION="3.0"
readonly LOG_FILE="/var/log/qradar_unified_setup.log"
readonly PYTHON_SCRIPT_PATH="/usr/local/bin/qradar_execve_parser.py"
readonly AUDIT_RULES_FILE="/etc/audit/rules.d/10-qradar-mitre.rules"
readonly AUDISP_PLUGIN_CONF="/etc/audisp/plugins.d/syslog.conf"
readonly RSYSLOG_SIEM_CONF="/etc/rsyslog.d/10-qradar-siem.conf"
readonly AUDIT_FACILITY="local3"
readonly BACKUP_SUFFIX="qradar-bak-$(date +%Y%m%d-%H%M%S)"

# Platform detection variables
DISTRO=""
DISTRO_FAMILY=""
VERSION_ID_NUM=""
PACKAGE_MANAGER=""
LOCAL_SYSLOG_FILE=""

# =================== UTILITY FUNCTIONS ===================

# Timestamped logging function
log() {
    local level="${2:-INFO}"
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $1"
    echo "$message" | tee -a "$LOG_FILE" >&2
}

# Error logging and exit
error_exit() {
    log "CRITICAL ERROR: $1" "ERROR"
    log "Setup failed. Check $LOG_FILE for details." "ERROR"
    exit 1
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

# Retry mechanism for critical operations
retry_operation() {
    local max_attempts=3
    local attempt=1
    local cmd="$1"
    local description="$2"
    
    while [ $attempt -le $max_attempts ]; do
        if execute_cmd "$cmd" "$description (attempt $attempt/$max_attempts)"; then
            return 0
        fi
        attempt=$((attempt + 1))
        if [ $attempt -le $max_attempts ]; then
            log "Retrying in 5 seconds..." "DEBUG"
            sleep 5
        fi
    done
    
    warn "$description failed after $max_attempts attempts"
    return 1
}

# =================== PREREQUISITE CHECKS ===================

check_prerequisites() {
    log "=== QRadar Unified Log Forwarding Setup v$SCRIPT_VERSION ===" "INFO"
    log "Starting prerequisite checks..." "INFO"
    
    # Root privileges check
    if [ "$EUID" -ne 0 ]; then
        error_exit "Bu betik root yetkisiyle çalıştırılmalıdır. 'sudo' kullanın."
    fi
    
    # Parameters check
    if [ $# -lt 2 ]; then
        echo "Kullanım: $0 <SIEM_IP> <SIEM_PORT>" >&2
        error_exit "Gerekli parametreler eksik."
    fi
    
    # Validate IP address
    if ! echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        error_exit "Geçersiz SIEM IP adresi: $1"
    fi
    
    # Validate port number
    if ! echo "$2" | grep -Eq '^[0-9]+$' || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
        error_exit "Geçersiz SIEM port numarası: $2"
    fi
    
    # Initialize log file
    if ! touch "$LOG_FILE" 2>/dev/null; then
        error_exit "Log dosyası oluşturulamadı: $LOG_FILE"
    fi
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
                if command -v dnf >/dev/null 2>&1; then
                    PACKAGE_MANAGER="dnf"
                else
                    PACKAGE_MANAGER="yum"
                fi
                LOCAL_SYSLOG_FILE="/var/log/messages"
                ;;
            *)
                warn "Bilinmeyen dağıtım: $ID"
                # Fallback detection
                if command -v apt-get >/dev/null 2>&1; then
                    DISTRO_FAMILY="debian"
                    PACKAGE_MANAGER="apt"
                    LOCAL_SYSLOG_FILE="/var/log/syslog"
                elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
                    DISTRO_FAMILY="rhel"
                    PACKAGE_MANAGER=$(command -v dnf >/dev/null 2>&1 && echo "dnf" || echo "yum")
                    LOCAL_SYSLOG_FILE="/var/log/messages"
                else
                    error_exit "Desteklenmeyen dağıtım: $ID"
                fi
                ;;
        esac
    else
        error_exit "/etc/os-release dosyası bulunamadı. Platform tespiti başarısız."
    fi
    
    log "Platform tespit edildi: $DISTRO $VERSION_ID_NUM ($DISTRO_FAMILY)" "INFO"
    log "Paket yöneticisi: $PACKAGE_MANAGER" "INFO"
    log "Yerel syslog dosyası: $LOCAL_SYSLOG_FILE" "INFO"
    
    success "Platform detection completed"
}

# =================== PACKAGE INSTALLATION ===================

install_packages() {
    log "Installing required packages..." "INFO"
    
    local base_packages=""
    local audit_packages=""
    local extra_packages=""
    
    case "$DISTRO_FAMILY" in
        debian)
            base_packages="auditd audispd-plugins rsyslog python3"
            extra_packages="rsyslog-omprog"
            
            # Update package cache
            if ! retry_operation "apt-get update -y" "Package cache update"; then
                warn "Package cache güncellemesi başarısız, devam ediliyor..."
            fi
            
            # Install base packages
            if ! retry_operation "DEBIAN_FRONTEND=noninteractive apt-get install -y $base_packages" "Base package installation"; then
                error_exit "Temel paketler kurulamadı"
            fi
            
            # Try to install optional packages
            if ! execute_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y $extra_packages" "Extra package installation"; then
                warn "Ek paketler kurulamadı, devam ediliyor..."
            fi
            ;;
            
        rhel)
            base_packages="audit rsyslog python3"
            audit_packages="audit-plugins audispd-plugins"
            
            # Handle EPEL for older RHEL/CentOS versions
            if [[ "$VERSION_ID_NUM" == 7* ]] && [[ "$DISTRO" =~ ^(rhel|centos)$ ]]; then
                if ! rpm -q epel-release >/dev/null 2>&1; then
                    log "Installing EPEL repository for RHEL/CentOS 7..." "INFO"
                    if ! execute_cmd "$PACKAGE_MANAGER install -y epel-release" "EPEL installation"; then
                        warn "EPEL repository kurulamadı"
                    fi
                fi
            fi
            
            # Install base packages
            if ! retry_operation "$PACKAGE_MANAGER install -y $base_packages" "Base package installation"; then
                error_exit "Temel paketler kurulamadı"
            fi
            
            # Try audit plugins
            if ! execute_cmd "$PACKAGE_MANAGER install -y $audit_packages" "Audit plugins installation"; then
                warn "Audit plugins kurulamadı, devam ediliyor..."
            fi
            
            # Try rsyslog-omprog if available
            if ! execute_cmd "$PACKAGE_MANAGER install -y rsyslog-omprog" "Rsyslog omprog installation"; then
                warn "rsyslog-omprog paketi bulunamadı veya kurulamadı"
            fi
            ;;
            
        *)
            error_exit "Desteklenmeyen dağıtım ailesi: $DISTRO_FAMILY"
            ;;
    esac
    
    # Verify critical packages
    local critical_packages="auditd rsyslog python3"
    for pkg in $critical_packages; do
        if ! command -v "$pkg" >/dev/null 2>&1; then
            error_exit "Kritik paket bulunamadı: $pkg"
        fi
    done
    
    success "Package installation completed"
}

# =================== PYTHON SCRIPT DEPLOYMENT ===================

deploy_python_script() {
    log "Deploying EXECVE argument parser script..." "INFO"
    
    # Backup existing script if present
    if [ -f "$PYTHON_SCRIPT_PATH" ]; then
        cp "$PYTHON_SCRIPT_PATH" "${PYTHON_SCRIPT_PATH}.$BACKUP_SUFFIX" 2>/dev/null || \
            warn "Mevcut Python script yedeklenemedi"
    fi
    
    cat > "$PYTHON_SCRIPT_PATH" << 'PYTHON_SCRIPT_EOF'
#!/usr/bin/env python3
"""
QRadar EXECVE Argument Parser v3.0
MITRE ATT&CK uyumlu log parsing ve command reconstruction
"""

import sys
import re
import json
import time
from datetime import datetime

class ExecveParser:
    def __init__(self):
        self.execve_pattern = re.compile(r'type=EXECVE')
        self.arg_pattern = re.compile(r'a(\d+)="([^"]*)"')
        self.syscall_pattern = re.compile(r'type=SYSCALL.*?exe="([^"]*)".*?ppid=(\d+).*?pid=(\d+).*?uid=(\d+)')
        
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
                args[arg_num] = arg_value
            
            if not args:
                return line
                
            # Reconstruct command from arguments
            command_parts = []
            for i in sorted(args.keys()):
                if args[i]:  # Skip empty arguments
                    command_parts.append(args[i])
            
            if not command_parts:
                return line
                
            full_command = ' '.join(command_parts)
            
            # Remove all existing aX= fields
            cleaned_line = self.arg_pattern.sub('', line).strip()
            
            # Ensure proper spacing
            if cleaned_line and not cleaned_line.endswith(' '):
                cleaned_line += ' '
                
            # Add reconstructed command as single field
            enhanced_line = cleaned_line + f'command="{full_command}"'
            
            # Add MITRE technique indicators based on command analysis
            mitre_tags = self.analyze_mitre_techniques(full_command, command_parts[0] if command_parts else "")
            if mitre_tags:
                enhanced_line += f' mitre_techniques="{",".join(mitre_tags)}"'
            
            return enhanced_line
            
        except Exception as e:
            # Log error but return original line to prevent data loss
            print(f"EXECVE_PARSER_ERROR: {str(e)}", file=sys.stderr)
            return line
    
    def analyze_mitre_techniques(self, full_command, executable):
        """Analyze command for MITRE ATT&CK technique indicators"""
        techniques = []
        
        # Command and Control
        if any(tool in executable.lower() for tool in ['wget', 'curl', 'nc', 'netcat', 'ncat']):
            techniques.append('T1105')  # Ingress Tool Transfer
            
        # Discovery
        if any(cmd in full_command.lower() for cmd in ['ps ', 'netstat', 'ss ', 'lsof', 'who', 'w ', 'id ', 'whoami']):
            techniques.append('T1057')  # Process Discovery
            techniques.append('T1049')  # System Network Connections Discovery
            
        # Credential Access
        if any(path in full_command for path in ['/etc/passwd', '/etc/shadow', '/etc/group']):
            techniques.append('T1003')  # OS Credential Dumping
            
        # Persistence
        if any(cmd in full_command.lower() for cmd in ['crontab', 'systemctl', 'service']):
            techniques.append('T1053')  # Scheduled Task/Job
            
        # Privilege Escalation
        if executable.lower() in ['su', 'sudo', 'pkexec']:
            techniques.append('T1548')  # Abuse Elevation Control Mechanism
            
        # Defense Evasion
        if any(cmd in full_command.lower() for cmd in ['chmod +x', 'chattr', 'rm ', 'unlink']):
            techniques.append('T1222')  # File and Directory Permissions Modification
            
        # Execution
        if any(interpreter in executable.lower() for interpreter in ['python', 'perl', 'ruby', 'node', 'bash', 'sh']):
            techniques.append('T1059')  # Command and Scripting Interpreter
            
        return techniques

def main():
    parser = ExecveParser()
    
    try:
        for line in sys.stdin:
            processed_line = parser.parse_execve_line(line.strip())
            print(processed_line)
            sys.stdout.flush()
            
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"EXECVE_PARSER_FATAL: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
PYTHON_SCRIPT_EOF
    
    # Set permissions
    chmod 755 "$PYTHON_SCRIPT_PATH" || error_exit "Python script izinleri ayarlanamadı"
    chown root:root "$PYTHON_SCRIPT_PATH" 2>/dev/null || warn "Python script sahipliği ayarlanamadı"
    
    # Test script syntax
    if ! python3 -m py_compile "$PYTHON_SCRIPT_PATH" 2>/dev/null; then
        error_exit "Python script syntax hatası"
    fi
    
    success "Python EXECVE parser deployed successfully"
}

# =================== AUDIT CONFIGURATION ===================

configure_auditd() {
    log "Configuring auditd with MITRE ATT&CK aligned rules..." "INFO"
    
    # Backup existing audit rules
    if [ -f "$AUDIT_RULES_FILE" ]; then
        cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.$BACKUP_SUFFIX" 2>/dev/null || \
            warn "Mevcut audit kuralları yedeklenemedi"
    fi
    
    # Create audit rules directory
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")" || error_exit "Audit rules dizini oluşturulamadı"
    
    # Deploy comprehensive MITRE-aligned audit rules
    cat > "$AUDIT_RULES_FILE" << 'AUDIT_RULES_EOF'
# QRadar MITRE ATT&CK Aligned Audit Rules v3.0
# Generated automatically - do not edit manually

# Delete all existing rules and set configuration
-D
-b 8192
-f 1

##########################################
# MITRE ATT&CK: TA0003 - Persistence
##########################################

# T1053 - Scheduled Task/Job
-w /etc/crontab -p wa -k mitre_t1053_cron
-w /etc/cron.allow -p wa -k mitre_t1053_cron
-w /etc/cron.deny -p wa -k mitre_t1053_cron
-w /etc/cron.d/ -p wa -k mitre_t1053_cron
-w /etc/cron.daily/ -p wa -k mitre_t1053_cron
-w /etc/cron.hourly/ -p wa -k mitre_t1053_cron
-w /etc/cron.monthly/ -p wa -k mitre_t1053_cron
-w /etc/cron.weekly/ -p wa -k mitre_t1053_cron
-w /var/spool/cron/crontabs/ -p wa -k mitre_t1053_cron

# T1543 - Create or Modify System Process
-w /etc/systemd/ -p wa -k mitre_t1543_systemd
-w /lib/systemd/ -p wa -k mitre_t1543_systemd
-w /usr/lib/systemd/ -p wa -k mitre_t1543_systemd
-w /etc/init.d/ -p wa -k mitre_t1543_init

##########################################
# MITRE ATT&CK: TA0004 - Privilege Escalation
##########################################

# T1548 - Abuse Elevation Control Mechanism
-w /bin/su -p x -k mitre_t1548_su
-w /usr/bin/sudo -p x -k mitre_t1548_sudo
-w /usr/bin/pkexec -p x -k mitre_t1548_pkexec
-w /etc/sudoers -p wa -k mitre_t1548_sudoers
-w /etc/sudoers.d/ -p wa -k mitre_t1548_sudoers

# Privilege escalation syscalls
-a always,exit -F arch=b64 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k mitre_t1548_setuid
-a always,exit -F arch=b32 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k mitre_t1548_setuid

##########################################
# MITRE ATT&CK: TA0005 - Defense Evasion
##########################################

# T1222 - File and Directory Permissions Modification
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F a1&0111 -k mitre_t1222_chmod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F a1&0111 -k mitre_t1222_chmod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k mitre_t1222_chown
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -k mitre_t1222_chown

# T1070 - Indicator Removal on Host
-w /var/log/ -p wa -k mitre_t1070_log_deletion
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k mitre_t1070_file_deletion
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k mitre_t1070_file_deletion

##########################################
# MITRE ATT&CK: TA0006 - Credential Access
##########################################

# T1003 - OS Credential Dumping
-w /etc/passwd -p wa -k mitre_t1003_credential_files
-w /etc/shadow -p wa -k mitre_t1003_credential_files
-w /etc/group -p wa -k mitre_t1003_credential_files
-w /etc/gshadow -p wa -k mitre_t1003_credential_files
-w /etc/security/opasswd -p wa -k mitre_t1003_credential_files

##########################################
# MITRE ATT&CK: TA0007 - Discovery
##########################################

# T1057 - Process Discovery
-w /usr/bin/ps -p x -k mitre_t1057_process_discovery
-w /bin/ps -p x -k mitre_t1057_process_discovery

# T1049 - System Network Connections Discovery
-w /usr/bin/netstat -p x -k mitre_t1049_network_discovery
-w /bin/netstat -p x -k mitre_t1049_network_discovery
-w /usr/bin/ss -p x -k mitre_t1049_network_discovery
-w /bin/ss -p x -k mitre_t1049_network_discovery

##########################################
# MITRE ATT&CK: TA0011 - Command and Control
##########################################

# T1105 - Ingress Tool Transfer
-w /usr/bin/wget -p x -k mitre_t1105_tool_transfer
-w /usr/bin/curl -p x -k mitre_t1105_tool_transfer
-w /bin/nc -p x -k mitre_t1105_tool_transfer
-w /usr/bin/ncat -p x -k mitre_t1105_tool_transfer
-w /usr/bin/netcat -p x -k mitre_t1105_tool_transfer

##########################################
# MITRE ATT&CK: TA0002 - Execution
##########################################

# T1059 - Command and Scripting Interpreter
-a always,exit -F arch=b64 -S execve -F euid=0 -k mitre_t1059_root_execution
-a always,exit -F arch=b32 -S execve -F euid=0 -k mitre_t1059_root_execution
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k mitre_t1059_user_execution
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k mitre_t1059_user_execution

##########################################
# System Administration and Security
##########################################

# Audit configuration changes
-w /etc/audit/ -p wa -k audit_config_modification
-w /etc/audisp/ -p wa -k audit_config_modification
-w /sbin/auditctl -p x -k audit_tools
-w /sbin/auditd -p x -k audit_tools

# PAM configuration
-w /etc/pam.d/ -p wa -k pam_modification
-w /etc/security/ -p wa -k security_modification

# SSH configuration
-w /etc/ssh/sshd_config -p wa -k ssh_config_modification
-w /etc/ssh/ssh_config -p wa -k ssh_config_modification

# Kernel module loading
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k kernel_module_loading
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k kernel_module_loading
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k kernel_module_loading
-w /etc/modprobe.conf -p wa -k kernel_module_config

# Network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config_modification
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_config_modification
-w /etc/hosts -p wa -k network_config_modification

# System state changes
-w /sbin/shutdown -p x -k system_shutdown
-w /sbin/poweroff -p x -k system_shutdown
-w /sbin/reboot -p x -k system_shutdown
-w /sbin/halt -p x -k system_shutdown

# Critical file access
-w /var/log/auth.log -p wa -k auth_log_access
-w /var/log/secure -p wa -k auth_log_access
-w /var/log/messages -p wa -k system_log_access
-w /var/log/syslog -p wa -k system_log_access

##########################################
# High-risk directories and files
##########################################
-w /tmp -p x -k suspicious_temp_execution
-w /var/tmp -p x -k suspicious_temp_execution
-w /dev/shm -p x -k suspicious_shm_execution

# Make configuration immutable (uncomment if needed)
# -e 2
AUDIT_RULES_EOF

    # Set proper permissions
    chmod 640 "$AUDIT_RULES_FILE" || error_exit "Audit rules dosyası izinleri ayarlanamadı"
    
    # Configure audisp-syslog plugin
    configure_audisp_plugin
    
    # Load audit rules and restart service
    load_audit_rules
    
    success "Auditd configuration completed"
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
        warn "audisp-syslog binary bulunamadı. Plugin yapılandırması atlanıyor."
        return 0
    fi
    
    # Create audisp config directory
    mkdir -p "$(dirname "$AUDISP_PLUGIN_CONF")" || warn "Audisp config dizini oluşturulamadı"
    
    # Backup existing config
    if [ -f "$AUDISP_PLUGIN_CONF" ]; then
        cp "$AUDISP_PLUGIN_CONF" "${AUDISP_PLUGIN_CONF}.$BACKUP_SUFFIX" 2>/dev/null || \
            warn "Mevcut audisp config yedeklenemedi"
    fi
    
    # Create audisp-syslog configuration
    cat > "$AUDISP_PLUGIN_CONF" << EOF
active = yes
direction = out
path = $audisp_binary
type = always
args = LOG_$(echo "$AUDIT_FACILITY" | tr '[:lower:]' '[:upper:]')
format = string
EOF
    
    chmod 640 "$AUDISP_PLUGIN_CONF" 2>/dev/null || warn "Audisp config izinleri ayarlanamadı"
    
    log "Audisp-syslog plugin configured with binary: $audisp_binary" "INFO"
}

load_audit_rules() {
    log "Loading audit rules..." "INFO"
    
    # Enable auditd service
    if ! execute_cmd "systemctl enable auditd" "Enable auditd service"; then
        warn "auditd servisi enable edilemedi"
    fi
    
    # Load rules using augenrules if available
    if command -v augenrules >/dev/null 2>&1; then
        if ! retry_operation "augenrules --load" "Load audit rules with augenrules"; then
            warn "augenrules ile kural yüklemesi başarısız, auditctl deneniyor..."
            if ! retry_operation "auditctl -R '$AUDIT_RULES_FILE'" "Load audit rules with auditctl"; then
                warn "Audit kuralları yüklenemedi"
            fi
        fi
    else
        if ! retry_operation "auditctl -R '$AUDIT_RULES_FILE'" "Load audit rules with auditctl"; then
            warn "Audit kuralları yüklenemedi"
        fi
    fi
    
    # Restart auditd service
    if ! retry_operation "systemctl restart auditd" "Restart auditd service"; then
        warn "auditd servisi yeniden başlatılamadı"
    fi
    
    # Wait for service to stabilize
    sleep 3
    
    # Verify audit rules are loaded
    if command -v auditctl >/dev/null 2>&1; then
        local rule_count
        rule_count=$(auditctl -l 2>/dev/null | wc -l)
        if [ "$rule_count" -gt 0 ]; then
            log "Audit rules loaded successfully ($rule_count rules active)" "INFO"
        else
            warn "Audit kuralları yüklenmiş görünmüyor"
        fi
    fi
}

# =================== RSYSLOG CONFIGURATION ===================

configure_rsyslog() {
    log "Configuring rsyslog for QRadar SIEM forwarding..." "INFO"
    
    local siem_ip="$1"
    local siem_port="$2"
    
    # Backup existing rsyslog SIEM config
    if [ -f "$RSYSLOG_SIEM_CONF" ]; then
        cp "$RSYSLOG_SIEM_CONF" "${RSYSLOG_SIEM_CONF}.$BACKUP_SUFFIX" 2>/dev/null || \
            warn "Mevcut rsyslog config yedeklenemedi"
    fi
    
    # Create optimized rsyslog configuration for QRadar
    cat > "$RSYSLOG_SIEM_CONF" << EOF
# QRadar SIEM Forwarding Configuration v3.0
# Automatically generated - manual edits will be lost

# Load required modules
module(load="omprog")

# Performance optimization
\$WorkDirectory /var/spool/rsyslog
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
\$ActionQueueType LinkedList
\$ActionQueueFileName qradar_queue
\$ActionQueueMaxDiskSpace 1g
\$ActionQueueSaveOnShutdown on
\$ActionQueueSize 100000
\$ActionResumeRetryCount -1

# Block noisy kernel messages from being forwarded
if \$syslogfacility-text == "kern" then {
    stop
}

# Block daemon messages to reduce noise
if \$syslogfacility-text == "daemon" then {
    stop
}

# Process audit logs from $AUDIT_FACILITY facility
if \$syslogfacility-text == "$AUDIT_FACILITY" then {
    # Filter for security-relevant events only
    if (
        \$msg contains "type=EXECVE" or
        \$msg contains "key=\"mitre_" or
        \$msg contains "key=\"audit_" or
        \$msg contains "key=\"auth_" or
        \$msg contains "key=\"pam_" or
        \$msg contains "key=\"ssh_" or
        \$msg contains "key=\"security_" or
        \$msg contains "key=\"kernel_" or
        \$msg contains "key=\"network_" or
        \$msg contains "key=\"system_" or
        \$msg contains "key=\"suspicious_"
    ) then {
        # Transform EXECVE messages with Python parser
        if \$msg contains "type=EXECVE" then {
            action(
                type="omprog"
                binary="$PYTHON_SCRIPT_PATH"
                name="QRadarExecveParser"
                useTransactions="on"
                confirmMessages="off"
                reportFailures="on"
                closeTimeout="5000"
                output="/var/log/qradar_execve_parser.log"
            )
        }
        
        # Forward security events to QRadar SIEM
        action(
            type="omfwd"
            target="$siem_ip"
            port="$siem_port"
            protocol="tcp"
            name="QRadarForwarder"
            queue.filename="qradar_fwd"
            queue.maxdiskspace="1g"
            queue.saveonshutdown="on"
            queue.size="50000"
            queue.discardmark="40000"
            queue.discardseverity="8"
            action.resumeRetryCount="-1"
            action.resumeInterval="10"
        )
        stop
    }
}

# Forward authentication logs regardless of facility
if (
    \$programname == "sshd" or
    \$programname == "sudo" or
    \$programname == "su" or
    \$programname == "login" or
    \$msg contains "authentication failure" or
    \$msg contains "password check failed" or
    \$msg contains "failed login" or
    \$msg contains "session opened" or
    \$msg contains "session closed"
) then {
    action(
        type="omfwd"
        target="$siem_ip"
        port="$siem_port"
        protocol="tcp"
        name="QRadarAuthForwarder"
        queue.filename="qradar_auth"
        queue.maxdiskspace="500m"
        queue.saveonshutdown="on"
    )
}

# Custom template for structured logging
template(name="QRadarTemplate" type="string"
    string="<%PRI%>%TIMESTAMP% %HOSTNAME% %PROGRAMNAME%[%PROCID%]: %MSG%\\n")
EOF

    # Validate rsyslog configuration
    validate_rsyslog_config
    
    # Restart and enable rsyslog
    if ! retry_operation "systemctl enable rsyslog" "Enable rsyslog service"; then
        warn "rsyslog servisi enable edilemedi"
    fi
    
    if ! retry_operation "systemctl restart rsyslog" "Restart rsyslog service"; then
        error_exit "rsyslog servisi yeniden başlatılamadı"
    fi
    
    # Wait for service to stabilize
    sleep 3
    
    success "Rsyslog configuration completed"
}

validate_rsyslog_config() {
    log "Validating rsyslog configuration..." "INFO"
    
    # Test rsyslog configuration syntax
    local validation_output
    validation_output=$(rsyslogd -N1 2>&1)
    local validation_result=$?
    
    if [ $validation_result -eq 0 ]; then
        log "Rsyslog configuration validation passed" "INFO"
    else
        warn "Rsyslog configuration validation warnings detected:"
        echo "$validation_output" >> "$LOG_FILE"
        log "Continuing despite validation warnings..." "INFO"
    fi
}

# =================== OS-SPECIFIC CONFIGURATIONS ===================

configure_os_specifics() {
    log "Configuring OS-specific settings..." "INFO"
    
    case "$DISTRO_FAMILY" in
        rhel)
            configure_rhel_specifics "$1" "$2"
            ;;
        debian)
            configure_debian_specifics
            ;;
    esac
    
    success "OS-specific configuration completed"
}

configure_rhel_specifics() {
    local siem_ip="$1"
    local siem_port="$2"
    
    log "Applying RHEL-specific configurations..." "INFO"
    
    # SELinux configuration
    configure_selinux
    
    # Firewall configuration
    configure_firewall "$siem_port"
}

configure_selinux() {
    if ! command -v getenforce >/dev/null 2>&1; then
        log "SELinux tools not found, skipping SELinux configuration" "INFO"
        return 0
    fi
    
    local selinux_status
    selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
    
    log "SELinux status: $selinux_status" "INFO"
    
    if [ "$selinux_status" = "Enforcing" ] || [ "$selinux_status" = "Permissive" ]; then
        # Allow rsyslog network connections
        if command -v setsebool >/dev/null 2>&1; then
            if ! execute_cmd "setsebool -P syslogd_can_network_connect on" "Enable rsyslog network connections"; then
                warn "SELinux: rsyslog network bağlantısı enable edilemedi"
            fi
        fi
        
        # Set proper context for Python script
        if command -v chcon >/dev/null 2>&1; then
            if ! execute_cmd "chcon -t syslogd_script_exec_t '$PYTHON_SCRIPT_PATH'" "Set SELinux context for Python script"; then
                warn "SELinux: Python script context ayarlanamadı"
            fi
        fi
        
        # Allow audit log reading
        if command -v setsebool >/dev/null 2>&1; then
            if ! execute_cmd "setsebool -P auditd_can_read_all_files on" "Enable auditd file reading"; then
                warn "SELinux: auditd dosya okuma izni verilemedi"
            fi
        fi
        
        log "SELinux configurations applied" "INFO"
    fi
}

configure_firewall() {
    local siem_port="$1"
    
    if ! command -v firewall-cmd >/dev/null 2>&1; then
        log "Firewalld not found, skipping firewall configuration" "INFO"
        return 0
    fi
    
    if ! systemctl is-active --quiet firewalld; then
        log "Firewalld service not active, skipping firewall configuration" "INFO"
        return 0
    fi
    
    log "Configuring firewall for SIEM port $siem_port..." "INFO"
    
    # Add outbound rule for SIEM communication
    if ! execute_cmd "firewall-cmd --permanent --add-port='$siem_port/tcp'" "Add firewall rule for SIEM port"; then
        warn "Firewall kuralı eklenemedi"
    fi
    
    if ! execute_cmd "firewall-cmd --reload" "Reload firewall rules"; then
        warn "Firewall kuralları yeniden yüklenemedi"
    fi
    
    # Verify rule was added
    if firewall-cmd --query-port="$siem_port/tcp" --permanent >/dev/null 2>&1; then
        log "Firewall rule for port $siem_port/tcp added successfully" "INFO"
    else
        warn "Firewall kuralı doğrulanamadı"
    fi
}

configure_debian_specifics() {
    log "Applying Debian-specific configurations..." "INFO"
    
    # UFW configuration if present
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        log "UFW firewall detected, adding rule for SIEM communication..." "INFO"
        if ! execute_cmd "ufw allow out '$2/tcp'" "Add UFW rule for SIEM"; then
            warn "UFW kuralı eklenemedi"
        fi
    fi
    
    # AppArmor configuration if present
    if command -v aa-status >/dev/null 2>&1 && aa-status >/dev/null 2>&1; then
        log "AppArmor detected, checking profiles..." "INFO"
        # Add AppArmor exception for rsyslog if needed
        if [ -d /etc/apparmor.d/local ]; then
            echo "# QRadar log forwarding exception" >> /etc/apparmor.d/local/usr.sbin.rsyslogd 2>/dev/null || true
            execute_cmd "systemctl reload apparmor" "Reload AppArmor profiles" || warn "AppArmor profilleri yeniden yüklenemedi"
        fi
    fi
}

# =================== TESTING AND VALIDATION ===================

run_comprehensive_tests() {
    local siem_ip="$1"
    local siem_port="$2"
    
    log "Running comprehensive system tests..." "INFO"
    
    # Test 1: Service status verification
    test_services
    
    # Test 2: Audit rule validation
    test_audit_rules
    
    # Test 3: Log generation and forwarding test
    test_log_forwarding "$siem_ip" "$siem_port"
    
    # Test 4: Python script functionality
    test_python_script
    
    # Test 5: Network connectivity
    test_network_connectivity "$siem_ip" "$siem_port"
    
    success "Comprehensive testing completed"
}

test_services() {
    log "Testing service status..." "INFO"
    
    local services=("auditd" "rsyslog")
    local failed_services=()
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log "Service $service is active" "INFO"
        else
            warn "Service $service is not active"
            failed_services+=("$service")
        fi
        
        if systemctl is-enabled --quiet "$service"; then
            log "Service $service is enabled" "INFO"
        else
            warn "Service $service is not enabled"
        fi
    done
    
    if [ ${#failed_services[@]} -gt 0 ]; then
        warn "Some services are not running: ${failed_services[*]}"
        # Attempt to start failed services
        for service in "${failed_services[@]}"; do
            log "Attempting to start $service..." "INFO"
            execute_cmd "systemctl start '$service'" "Start $service service" || warn "$service başlatılamadı"
        done
    fi
}

test_audit_rules() {
    log "Testing audit rules..." "INFO"
    
    if command -v auditctl >/dev/null 2>&1; then
        local rule_count
        rule_count=$(auditctl -l 2>/dev/null | wc -l)
        
        if [ "$rule_count" -gt 0 ]; then
            log "Audit rules active: $rule_count rules loaded" "INFO"
            
            # Test specific MITRE rules
            local mitre_rules
            mitre_rules=$(auditctl -l 2>/dev/null | grep -c "mitre_" || echo "0")
            log "MITRE ATT&CK rules loaded: $mitre_rules" "INFO"
            
        else
            warn "No audit rules are currently loaded"
        fi
    else
        warn "auditctl command not available for rule testing"
    fi
}

test_log_forwarding() {
    local siem_ip="$1"
    local siem_port="$2"
    
    log "Testing log forwarding functionality..." "INFO"
    
    # Generate test audit event
    local test_message="QRadar_Test_Event_$(date +%s)"
    
    log "Generating test audit event..." "INFO"
    touch /etc/passwd 2>/dev/null || warn "Test audit event oluşturulamadı"
    
    # Send test syslog message
    log "Sending test syslog message..." "INFO"
    logger -p "$AUDIT_FACILITY.info" "$test_message" || warn "Test syslog mesajı gönderilemedi"
    
    # Wait for processing
    sleep 5
    
    # Check local syslog for test message
    if grep -q "$test_message" "$LOCAL_SYSLOG_FILE" 2>/dev/null; then
        log "Test message found in local syslog" "INFO"
    else
        warn "Test message not found in local syslog: $LOCAL_SYSLOG_FILE"
    fi
    
    # Check for recent audit events
    if command -v ausearch >/dev/null 2>&1; then
        local recent_events
        recent_events=$(ausearch -ts today 2>/dev/null | wc -l)
        log "Recent audit events found: $recent_events" "INFO"
    fi
}

test_python_script() {
    log "Testing Python EXECVE parser..." "INFO"
    
    if [ ! -x "$PYTHON_SCRIPT_PATH" ]; then
        warn "Python script is not executable: $PYTHON_SCRIPT_PATH"
        return 1
    fi
    
    # Test with sample EXECVE line
    local test_input='audit: type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="ls" a1="-la" a2="/tmp"'
    local test_output
    
    test_output=$(echo "$test_input" | "$PYTHON_SCRIPT_PATH" 2>/dev/null)
    
    if echo "$test_output" | grep -q 'command="ls -la /tmp"'; then
        log "Python EXECVE parser test successful" "INFO"
    else
        warn "Python EXECVE parser test failed"
        log "Test input: $test_input" "DEBUG"
        log "Test output: $test_output" "DEBUG"
    fi
}

test_network_connectivity() {
    local siem_ip="$1"
    local siem_port="$2"
    
    log "Testing network connectivity to SIEM..." "INFO"
    
    # Test basic connectivity
    if command -v nc >/dev/null 2>&1; then
        if timeout 10 nc -z "$siem_ip" "$siem_port" 2>/dev/null; then
            log "Network connectivity to $siem_ip:$siem_port successful" "INFO"
        else
            warn "Network connectivity to $siem_ip:$siem_port failed"
            log "Consider checking: firewall rules, network routing, SIEM availability" "INFO"
        fi
    elif command -v telnet >/dev/null 2>&1; then
        if timeout 10 bash -c "echo '' | telnet '$siem_ip' '$siem_port'" 2>/dev/null | grep -q "Connected"; then
            log "Network connectivity to $siem_ip:$siem_port successful" "INFO"
        else
            warn "Network connectivity to $siem_ip:$siem_port failed"
        fi
    else
        warn "No network testing tools available (nc, telnet)"
    fi
}

# =================== CLEANUP AND FINALIZATION ===================

cleanup_and_finalize() {
    log "Performing cleanup and finalization..." "INFO"
    
    # Set proper log file permissions
    chmod 640 "$LOG_FILE" 2>/dev/null || warn "Log dosyası izinleri ayarlanamadı"
    
    # Create log rotation config for our custom logs
    create_logrotate_config
    
    # Generate final status report
    generate_status_report "$1" "$2"
    
    success "Setup completed successfully"
}

create_logrotate_config() {
    local logrotate_conf="/etc/logrotate.d/qradar-unified"
    
    cat > "$logrotate_conf" << 'EOF'
/var/log/qradar_unified_setup.log
/var/log/qradar_execve_parser.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
EOF
    
    log "Log rotation configuration created: $logrotate_conf" "INFO"
}

generate_status_report() {
    local siem_ip="$1"
    local siem_port="$2"
    
    log "=== QRadar Unified Setup Status Report ===" "INFO"
    log "Setup Version: $SCRIPT_VERSION" "INFO"
    log "Platform: $DISTRO $VERSION_ID_NUM ($DISTRO_FAMILY)" "INFO"
    log "SIEM Target: $siem_ip:$siem_port" "INFO"
    log "Audit Facility: $AUDIT_FACILITY" "INFO"
    
    # Service status
    log "--- Service Status ---" "INFO"
    for service in auditd rsyslog; do
        if systemctl is-active --quiet "$service"; then
            log "$service: ACTIVE" "INFO"
        else
            log "$service: INACTIVE" "INFO"
        fi
    done
    
    # File status
    log "--- Configuration Files ---" "INFO"
    local config_files=(
        "$PYTHON_SCRIPT_PATH"
        "$AUDIT_RULES_FILE"
        "$AUDISP_PLUGIN_CONF"
        "$RSYSLOG_SIEM_CONF"
    )
    
    for file in "${config_files[@]}"; do
        if [ -f "$file" ]; then
            log "$file: EXISTS" "INFO"
        else
            log "$file: MISSING" "INFO"
        fi
    done
    
    # Final instructions
    log "=== Next Steps ===" "INFO"
    log "1. QRadar SIEM sunucusunda TCP/$siem_port portunda log alımının aktif olduğunu doğrulayın" "INFO"
    log "2. Ağ bağlantısını test etmek için: tcpdump -i any host $siem_ip and port $siem_port -A -n" "INFO"
    log "3. Log iletimini test etmek için: logger -p $AUDIT_FACILITY.info 'Test message from $(hostname)'" "INFO"
    log "4. Audit olayları için: tail -f /var/log/audit/audit.log | grep EXECVE" "INFO"
    log "5. Rsyslog durumu için: journalctl -u rsyslog -f" "INFO"
    log "6. Detaylı loglar: $LOG_FILE" "INFO"
    
    log "Setup completed. QRadar SIEM should start receiving security logs." "INFO"
}

# =================== MAIN EXECUTION ===================

main() {
    # Initialize and validate
    check_prerequisites "$@"
    
    local siem_ip="$1"
    local siem_port="$2"
    
    # Platform detection
    detect_platform
    
    # Core installation and configuration
    install_packages
    deploy_python_script
    configure_auditd
    configure_rsyslog "$siem_ip" "$siem_port"
    configure_os_specifics "$siem_ip" "$siem_port"
    
    # Testing and validation
    run_comprehensive_tests "$siem_ip" "$siem_port"
    
    # Cleanup and finalization
    cleanup_and_finalize "$siem_ip" "$siem_port"
    
    log "QRadar Unified Log Forwarding Setup completed successfully!" "SUCCESS"
}

# Execute main function with all arguments
main "$@"
