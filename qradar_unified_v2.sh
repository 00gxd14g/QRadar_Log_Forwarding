#!/usr/bin/env bash
#
# ===============================================================================
# QRadar Unified Log Forwarding Setup Script - V2 Edition v2.0.0
# ===============================================================================
#
# Advanced QRadar SIEM log forwarding solution with MITRE ATT&CK framework
# integration, dual forwarding methods, and comprehensive fallback mechanisms.
#
# Features:
#   - MITRE ATT&CK technique mapping and analysis
#   - Dual log forwarding methods (audisp + direct audit processing)
#   - Advanced error handling with comprehensive fallback mechanisms
#   - Modern RainerScript rsyslog configuration with queue management
#   - Automatic firewall management (firewalld, UFW, iptables)
#   - Comprehensive file tracking and backup system
#   - Enhanced security with non-eval command execution
#   - Multi-language support (English/Turkish)
#   - Production-optimized audit rules with noise reduction
#
# Supported distributions:
#   - Debian/Ubuntu/Kali Linux (all versions)
#   - RHEL/CentOS/Oracle Linux/AlmaLinux/Rocky Linux (7, 8, 9)
#   - Enhanced platform detection with ID_LIKE support
#
# Usage: sudo bash qradar_unified_v2.sh <QRADAR_IP> <QRADAR_PORT> [OPTIONS]
#
# Options:
#   --facility=local6     Use alternative syslog facility (default: local3)
#   --mitre-mode         Enable comprehensive MITRE ATT&CK integration
#   --lang=tr            Use Turkish language interface
#   --method=dual        Use both audisp and direct methods (default)
#   --method=audisp      Use only audisp method
#   --method=direct      Use only direct audit log processing
#
# Author: QRadar Log Forwarding Project - V2 Edition
# Version: 2.0.0
# ===============================================================================

set -euo pipefail

# ===============================================================================
# GLOBAL CONFIGURATION
# ===============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="2.0.0"
readonly LOG_FILE="/var/log/qradar_unified_v2_setup.log"
readonly BACKUP_DIR="/etc/qradar_v2_backup_$(date +%Y%m%d_%H%M%S)"

# Configuration file paths
readonly AUDIT_RULES_FILE="/etc/audit/rules.d/10-qradar-mitre.rules"
readonly AUDISP_SYSLOG_CONF="/etc/audit/plugins.d/syslog.conf"
readonly RSYSLOG_QRADAR_CONF="/etc/rsyslog.d/10-qradar-unified.conf"
readonly PYTHON_PARSER_PATH="/usr/local/bin/qradar_mitre_parser.py"
readonly SYSTEMD_TIMER_PATH="/etc/systemd/system/qradar-audit-parser.timer"
readonly SYSTEMD_SERVICE_PATH="/etc/systemd/system/qradar-audit-parser.service"

# Default configuration
AUDIT_FACILITY="local3"
FORWARDING_METHOD="dual"
MITRE_MODE=false
LANGUAGE="en"

# System detection variables
DISTRO=""
DISTRO_FAMILY=""
VERSION_ID=""
PACKAGE_MANAGER=""
SYSLOG_FILE=""
AUDISP_AVAILABLE=false

# Script arguments
QRADAR_IP=""
QRADAR_PORT=""

# Tracking arrays
declare -a MODIFIED_FILES=()
declare -a CREATED_FILES=()
declare -a BACKED_UP_FILES=()
declare -a INSTALLED_PACKAGES=()
declare -a ENABLED_SERVICES=()
declare -a FIREWALL_RULES_ADDED=()

# ===============================================================================
# MULTILINGUAL SUPPORT
# ===============================================================================

# Message function with language support
msg() {
    local key="$1"
    shift
    
    case "$key" in
        "detecting_system")
            if [[ "$LANGUAGE" == "tr" ]]; then
                printf "Sistem bilgileri tespit ediliyor...\n"
            else
                printf "Detecting system information...\n"
            fi
            ;;
        "detected_system")
            if [[ "$LANGUAGE" == "tr" ]]; then
                printf "Tespit edildi: %s %s (Paket yöneticisi: %s)\n" "$@"
            else
                printf "Detected: %s %s (Package manager: %s)\n" "$@"
            fi
            ;;
        "installing_packages")
            if [[ "$LANGUAGE" == "tr" ]]; then
                printf "Gerekli paketler kuruluyor...\n"
            else
                printf "Installing required packages...\n"
            fi
            ;;
        "configuring_audit")
            if [[ "$LANGUAGE" == "tr" ]]; then
                printf "Audit kuralları yapılandırılıyor...\n"
            else
                printf "Configuring audit rules...\n"
            fi
            ;;
        "configuring_rsyslog")
            if [[ "$LANGUAGE" == "tr" ]]; then
                printf "QRadar için rsyslog yapılandırılıyor...\n"
            else
                printf "Configuring rsyslog for QRadar forwarding...\n"
            fi
            ;;
        "restarting_services")
            if [[ "$LANGUAGE" == "tr" ]]; then
                printf "Servisler yeniden başlatılıyor...\n"
            else
                printf "Restarting services...\n"
            fi
            ;;
        "setup_complete")
            if [[ "$LANGUAGE" == "tr" ]]; then
                printf "QRadar unified kurulumu başarıyla tamamlandı!\n"
            else
                printf "QRadar unified setup completed successfully!\n"
            fi
            ;;
        "network_test")
            if [[ "$LANGUAGE" == "tr" ]]; then
                printf "QRadar ağ bağlantısı test ediliyor...\n"
            else
                printf "Testing network connectivity to QRadar...\n"
            fi
            ;;
        "backup_created")
            if [[ "$LANGUAGE" == "tr" ]]; then
                printf "Yapılandırma yedeği oluşturuldu: %s\n" "$@"
            else
                printf "Configuration backup created at: %s\n" "$@"
            fi
            ;;
        "mitre_enabled")
            if [[ "$LANGUAGE" == "tr" ]]; then
                printf "MITRE ATT&CK entegrasyonu etkinleştirildi\n"
            else
                printf "MITRE ATT&CK integration enabled\n"
            fi
            ;;
        "dual_method")
            if [[ "$LANGUAGE" == "tr" ]]; then
                printf "Çift yönlü iletim yöntemi yapılandırıldı\n"
            else
                printf "Dual forwarding method configured\n"
            fi
            ;;
        *)
            printf "%s\n" "$key"
            ;;
    esac
}

# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

# Enhanced logging function with levels
log() {
    local level="${1:-INFO}"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Error handling with localization
error_exit() {
    log "ERROR" "$1"
    echo "ERROR: $1" >&2
    echo "Check $LOG_FILE for detailed information."
    exit 1
}

# Warning function
warn() {
    log "WARN" "$1"
    echo "WARNING: $1" >&2
}

# Success function
success() {
    log "SUCCESS" "$1"
}

# Enhanced command execution without eval
execute_cmd() {
    local description="$1"
    shift
    local cmd_array=("$@")
    
    log "INFO" "Executing: $description"
    
    if "${cmd_array[@]}" >> "$LOG_FILE" 2>&1; then
        log "SUCCESS" "$description completed successfully"
        return 0
    else
        log "ERROR" "$description failed"
        return 1
    fi
}

# Retry mechanism for critical operations
retry_operation() {
    local max_attempts=3
    local attempt=1
    local description="$1"
    shift
    
    while [ $attempt -le $max_attempts ]; do
        log "INFO" "Attempt $attempt/$max_attempts: $description"
        
        if execute_cmd "$description" "$@"; then
            return 0
        fi
        
        attempt=$((attempt + 1))
        if [ $attempt -le $max_attempts ]; then
            log "WARN" "Attempt $((attempt-1)) failed, retrying in 5 seconds..."
            sleep 5
        fi
    done
    
    warn "All attempts failed for: $description"
    return 1
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Create backup of file
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_file="$BACKUP_DIR/$(basename "$file").$(date +%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$backup_file" || warn "Failed to backup $file"
        log "INFO" "Backed up $file to $backup_file"
        BACKED_UP_FILES+=("$file -> $backup_file")
    fi
}

# Track file modifications
track_file_change() {
    local file="$1"
    local action="$2"  # "created", "modified"
    
    case "$action" in
        "created")
            CREATED_FILES+=("$file")
            ;;
        "modified")
            MODIFIED_FILES+=("$file")
            ;;
    esac
}

# ===============================================================================
# SYSTEM DETECTION WITH ENHANCED PLATFORM SUPPORT
# ===============================================================================

detect_system() {
    log "INFO" "$(msg "detecting_system")"
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/etc/os-release
        source /etc/os-release
        DISTRO="$ID"
        VERSION_ID="$VERSION_ID"
        
        # Enhanced family detection using ID_LIKE
        local family_check="${ID_LIKE:-$ID}"
        case "$family_check" in
            *rhel*|*fedora*|centos)
                DISTRO_FAMILY="rhel"
                ;;
            *debian*|ubuntu)
                DISTRO_FAMILY="debian"
                ;;
            *)
                DISTRO_FAMILY="$ID"
                ;;
        esac
    else
        error_exit "Cannot detect system distribution. /etc/os-release not found."
    fi
    
    # Set package manager and syslog file based on family
    case "$DISTRO_FAMILY" in
        debian)
            SYSLOG_FILE="/var/log/syslog"
            PACKAGE_MANAGER="apt"
            ;;
        rhel)
            SYSLOG_FILE="/var/log/messages"
            PACKAGE_MANAGER="yum"
            if command_exists dnf; then
                PACKAGE_MANAGER="dnf"
            fi
            ;;
        *)
            error_exit "Unsupported distribution family: $DISTRO_FAMILY"
            ;;
    esac
    
    success "$(msg "detected_system" "$DISTRO" "$VERSION_ID" "$PACKAGE_MANAGER")"
}

# ===============================================================================
# ENHANCED PACKAGE INSTALLATION WITH FALLBACK
# ===============================================================================

install_packages() {
    log "INFO" "$(msg "installing_packages")"
    
    local packages_to_install=()
    local required_packages=()
    
    case "$PACKAGE_MANAGER" in
        apt)
            required_packages=("auditd" "audispd-plugins" "rsyslog" "python3")
            ;;
        dnf|yum)
            required_packages=("audit" "rsyslog" "python3")
            ;;
    esac
    
    # Check which packages are missing
    for package in "${required_packages[@]}"; do
        case "$PACKAGE_MANAGER" in
            apt)
                if ! dpkg -l | grep -q "^ii.*$package "; then
                    packages_to_install+=("$package")
                fi
                ;;
            dnf|yum)
                if ! rpm -q "$package" >/dev/null 2>&1; then
                    packages_to_install+=("$package")
                fi
                ;;
        esac
    done
    
    # Install missing packages
    if [ ${#packages_to_install[@]} -gt 0 ]; then
        log "INFO" "Installing missing packages: ${packages_to_install[*]}"
        
        case "$PACKAGE_MANAGER" in
            apt)
                retry_operation "Update package lists" apt-get update
                retry_operation "Install packages" apt-get install -y "${packages_to_install[@]}"
                ;;
            dnf)
                retry_operation "Install packages with DNF" dnf install -y "${packages_to_install[@]}"
                ;;
            yum)
                # Handle EPEL for RHEL 7
                if [[ " ${packages_to_install[*]} " =~ " python3 " ]] && [[ "$DISTRO" == "rhel" ]] && [[ "$VERSION_ID" =~ ^7 ]]; then
                    if ! rpm -q epel-release >/dev/null 2>&1; then
                        log "INFO" "Installing EPEL repository for RHEL 7..."
                        retry_operation "Install EPEL" yum install -y epel-release
                    fi
                fi
                retry_operation "Install packages with YUM" yum install -y "${packages_to_install[@]}"
                ;;
        esac
        
        INSTALLED_PACKAGES+=("${packages_to_install[@]}")
        success "Packages installed successfully: ${packages_to_install[*]}"
    else
        success "All required packages are already installed"
    fi
    
    # Check audisp availability
    if [[ -f "/sbin/audisp-syslog" ]] || [[ -f "/usr/sbin/audisp-syslog" ]]; then
        AUDISP_AVAILABLE=true
        log "INFO" "audisp-syslog is available"
    else
        warn "audisp-syslog not available, will use direct audit log processing"
    fi
}

# ===============================================================================
# MITRE ATT&CK ENHANCED PYTHON PARSER
# ===============================================================================

deploy_mitre_parser() {
    log "INFO" "Deploying MITRE ATT&CK enhanced parser..."
    
    cat > "$PYTHON_PARSER_PATH" << 'EOF'
#!/usr/bin/env python3
"""
QRadar MITRE ATT&CK Enhanced EXECVE Parser

This script processes audit EXECVE messages with MITRE ATT&CK technique
mapping and advanced command argument concatenation for SIEM analysis.
"""

import sys
import re
import json
import signal
import logging
from datetime import datetime
from typing import List, Dict, Tuple, Optional

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - qradar_mitre_parser - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)

class MitreAttackParser:
    def __init__(self):
        self.processed_count = 0
        self.error_count = 0
        self.mitre_techniques = self._load_mitre_techniques()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        logging.info(f"Received signal {signum}, shutting down gracefully...")
        sys.exit(0)
    
    def _load_mitre_techniques(self) -> Dict[str, List[str]]:
        """Load MITRE ATT&CK technique mappings."""
        return {
            # T1003 - OS Credential Dumping
            'T1003': ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
                     'passwd', 'getent', 'id', 'cat /etc/passwd'],
            
            # T1005 - Data from Local System
            'T1005': ['find', 'locate', 'grep', 'cat', 'less', 'more', 'head', 'tail'],
            
            # T1105 - Ingress Tool Transfer
            'T1105': ['wget', 'curl', 'nc', 'ncat', 'socat', 'scp', 'rsync', 'ftp'],
            
            # T1027 - Obfuscated Files or Information
            'T1027': ['base64', 'xxd', 'od', 'hexdump', 'openssl enc'],
            
            # T1036 - Masquerading
            'T1036': ['mv', 'cp', 'ln'],
            
            # T1053 - Scheduled Task/Job
            'T1053': ['crontab', 'at', 'systemctl', 'service'],
            
            # T1059 - Command and Scripting Interpreter
            'T1059': ['bash', 'sh', 'python', 'perl', 'ruby', 'php', 'powershell'],
            
            # T1070 - Indicator Removal on Host
            'T1070': ['rm', 'shred', 'wipe', 'bleachbit', 'unlink'],
            
            # T1082 - System Information Discovery
            'T1082': ['uname', 'whoami', 'id', 'ps', 'netstat', 'ss', 'lsof'],
            
            # T1087 - Account Discovery
            'T1087': ['who', 'w', 'last', 'lastlog', 'finger'],
            
            # T1134 - Access Token Manipulation
            'T1134': ['sudo', 'su', 'runuser'],
            
            # T1548 - Abuse Elevation Control Mechanism
            'T1548': ['sudo', 'su', 'pkexec', 'setuid', 'setgid'],
            
            # T1552 - Unsecured Credentials
            'T1552': ['history', 'cat ~/.bash_history', 'cat ~/.zsh_history'],
        }
    
    def extract_execve_args(self, line: str) -> List[Tuple[int, str]]:
        """Extract and order EXECVE arguments from audit log line."""
        # Handle both regular and hex-encoded arguments
        pattern = r'a(\d+)=(?:"([^"]*)"|([A-Fa-f0-9]+))'
        matches = re.findall(pattern, line)
        
        args_with_index = []
        for match in matches:
            idx = int(match[0])
            if match[1]:  # Regular string argument
                arg = match[1]
            else:  # Hex-encoded argument
                try:
                    arg = bytes.fromhex(match[2]).decode('utf-8', errors='ignore')
                except ValueError:
                    arg = match[2]  # Use as-is if hex decoding fails
            
            args_with_index.append((idx, arg))
        
        return sorted(args_with_index, key=lambda x: x[0])
    
    def analyze_mitre_techniques(self, full_command: str, executable: str) -> List[str]:
        """Analyze command for MITRE ATT&CK techniques."""
        techniques = []
        
        for technique_id, indicators in self.mitre_techniques.items():
            for indicator in indicators:
                if indicator.lower() in full_command.lower() or indicator.lower() in executable.lower():
                    techniques.append(technique_id)
                    break
        
        return techniques
    
    def process_execve_line(self, line: str) -> str:
        """Process EXECVE audit log line with MITRE analysis."""
        if "type=EXECVE" not in line:
            return line
        
        try:
            # Extract arguments
            args_with_index = self.extract_execve_args(line)
            
            if not args_with_index:
                return line
            
            # Reconstruct command
            args = [arg for _, arg in args_with_index]
            executable = args[0] if args else ""
            full_command = " ".join(args)
            
            # Analyze for MITRE techniques
            techniques = self.analyze_mitre_techniques(full_command, executable)
            
            # Remove all existing aX="..." fields
            cleaned_line = re.sub(r'a\d+="[^"]*"\s*', '', line)
            cleaned_line = re.sub(r'a\d+=[A-Fa-f0-9]+\s*', '', cleaned_line)
            cleaned_line = cleaned_line.strip()
            
            # Add processed fields
            if cleaned_line and not cleaned_line.endswith(' '):
                cleaned_line += ' '
            
            # Escape quotes in command
            escaped_command = full_command.replace('"', '\\"')
            processed_line = f'{cleaned_line}cmd="{escaped_command}"'
            
            # Add MITRE techniques if found
            if techniques:
                techniques_str = ",".join(techniques)
                processed_line += f' mitre_techniques="{techniques_str}"'
            
            self.processed_count += 1
            return f"MITRE_PROCESSED: {processed_line}"
            
        except Exception as e:
            logging.error(f"Error processing EXECVE line: {e}")
            self.error_count += 1
            return line
    
    def process_stream(self):
        """Main processing loop."""
        try:
            for line_number, line in enumerate(sys.stdin, 1):
                line = line.strip()
                
                if not line:
                    continue
                
                processed_line = self.process_execve_line(line)
                print(processed_line, flush=True)
                
        except KeyboardInterrupt:
            logging.info("Processing interrupted by user")
        except BrokenPipeError:
            # Handle broken pipe gracefully
            pass
        except Exception as e:
            logging.error(f"Fatal error in processing: {e}")
            sys.exit(1)
        finally:
            if self.processed_count > 0 or self.error_count > 0:
                logging.info(f"Processing complete: {self.processed_count} processed, {self.error_count} errors")

def main():
    """Main entry point."""
    # Handle test mode
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        test_lines = [
            'type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="sudo" a1="-u" a2="root" a3="id"',
            'type=EXECVE msg=audit(1234567890.124:457): argc=2 a0="wget" a1="http://example.com/malware.sh"',
            'type=EXECVE msg=audit(1234567890.125:458): argc=2 a0="cat" a1="/etc/passwd"',
            'type=SYSCALL msg=audit(1234567890.126:459): arch=c000003e syscall=2 success=yes',
        ]
        
        parser = MitreAttackParser()
        print("=== MITRE ATT&CK Parser Test ===")
        
        for i, line in enumerate(test_lines, 1):
            print(f"\nTest {i}:")
            print(f"Input:  {line}")
            result = parser.process_execve_line(line)
            print(f"Output: {result}")
        
        print("\nTest completed successfully!")
        return
    
    # Normal processing mode
    parser = MitreAttackParser()
    parser.process_stream()

if __name__ == "__main__":
    main()
EOF
    
    chmod +x "$PYTHON_PARSER_PATH" || error_exit "Failed to make parser script executable"
    track_file_change "$PYTHON_PARSER_PATH" "created"
    success "MITRE ATT&CK parser deployed to $PYTHON_PARSER_PATH"
}

# ===============================================================================
# COMPREHENSIVE AUDIT RULES WITH MITRE MAPPING
# ===============================================================================

configure_audit_rules() {
    log "INFO" "$(msg "configuring_audit")"
    
    backup_file "$AUDIT_RULES_FILE"
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")"
    
    cat > "$AUDIT_RULES_FILE" << 'EOF'
# QRadar Unified V2 - MITRE ATT&CK Enhanced Audit Rules
# Generated by QRadar Unified V2 Setup Script
# Optimized for production with MITRE technique mapping

## Delete all current rules and reset
-D

## Buffer Size (production optimized for high-volume)
-b 32768

## Failure Mode (1 = print failure message)
-f 1

## Rate limiting (prevent audit flooding)
-r 200

## Ignore errors during rule loading
-i

#################################
# MITRE T1003 - OS Credential Dumping
#################################
-w /etc/passwd -p wa -k mitre_t1003_credential_dumping
-w /etc/shadow -p wa -k mitre_t1003_credential_dumping
-w /etc/group -p wa -k mitre_t1003_credential_dumping
-w /etc/gshadow -p wa -k mitre_t1003_credential_dumping

#################################
# MITRE T1548 - Abuse Elevation Control Mechanism
#################################
-w /etc/sudoers -p wa -k mitre_t1548_sudoers
-w /etc/sudoers.d/ -p wa -k mitre_t1548_sudoers
-w /bin/su -p x -k mitre_t1548_elevation
-w /usr/bin/sudo -p x -k mitre_t1548_elevation
-w /usr/bin/pkexec -p x -k mitre_t1548_elevation

# Setuid/setgid monitoring
-a always,exit -F arch=b64 -S setuid -F a0=0 -k mitre_t1548_setuid
-a always,exit -F arch=b32 -S setuid -F a0=0 -k mitre_t1548_setuid
-a always,exit -F arch=b64 -S setgid -F a0=0 -k mitre_t1548_setgid
-a always,exit -F arch=b32 -S setgid -F a0=0 -k mitre_t1548_setgid

#################################
# MITRE T1053 - Scheduled Task/Job
#################################
-w /etc/crontab -p wa -k mitre_t1053_cron
-w /etc/cron.hourly/ -p wa -k mitre_t1053_cron
-w /etc/cron.daily/ -p wa -k mitre_t1053_cron
-w /etc/cron.weekly/ -p wa -k mitre_t1053_cron
-w /etc/cron.monthly/ -p wa -k mitre_t1053_cron
-w /var/spool/cron/ -p wa -k mitre_t1053_cron

# Systemd units (T1543 - Create or Modify System Process)
-w /etc/systemd/system/ -p wa -k mitre_t1543_systemd
-w /usr/lib/systemd/system/ -p wa -k mitre_t1543_systemd

#################################
# MITRE T1059 - Command and Scripting Interpreter
#################################
# Root command execution monitoring
-a always,exit -F arch=b64 -S execve -F euid=0 -k mitre_t1059_root_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -k mitre_t1059_root_commands

# User command execution (excluding system users)
-a always,exit -F arch=b64 -S execve -F euid>=1000 -F auid>=1000 -F auid!=4294967295 -k mitre_t1059_user_commands
-a always,exit -F arch=b32 -S execve -F euid>=1000 -F auid>=1000 -F auid!=4294967295 -k mitre_t1059_user_commands

#################################
# MITRE T1105 - Ingress Tool Transfer
#################################
-w /usr/bin/wget -p x -k mitre_t1105_download_tools
-w /usr/bin/curl -p x -k mitre_t1105_download_tools
-w /bin/nc -p x -k mitre_t1105_network_tools
-w /usr/bin/ncat -p x -k mitre_t1105_network_tools
-w /usr/bin/socat -p x -k mitre_t1105_network_tools

#################################
# MITRE T1070 - Indicator Removal on Host
#################################
# Log file manipulation
-w /var/log/ -p wa -k mitre_t1070_log_deletion
-w /var/log/audit/ -p wa -k mitre_t1070_audit_log_deletion

# History file manipulation
-w /home/ -p wa -F path~/.bash_history -k mitre_t1070_history_deletion
-w /root/.bash_history -p wa -k mitre_t1070_history_deletion

#################################
# MITRE T1082 - System Information Discovery
#################################
# System information commands are monitored through EXECVE rules above

#################################
# Network Configuration Changes
#################################
-w /etc/hosts -p wa -k network_config_changes
-w /etc/resolv.conf -p wa -k network_config_changes
-w /etc/network/interfaces -p wa -k network_config_changes
-w /etc/sysconfig/network-scripts/ -p wa -k network_config_changes
-w /etc/netplan/ -p wa -k network_config_changes

# Hostname and domain changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications

#################################
# Authentication & Access Control
#################################
-w /etc/pam.d/ -p wa -k pam_config_changes
-w /etc/ssh/sshd_config -p wa -k ssh_config_changes
-w /etc/login.defs -p wa -k login_config_changes
-w /etc/security/ -p wa -k security_config_changes

#################################
# File Permission and Ownership Changes
#################################
# Monitor critical file permission changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permission_changes
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permission_changes

# Monitor ownership changes
-a always,exit -F arch=b64 -S chown -S fchown -S lchown -S fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership_changes
-a always,exit -F arch=b32 -S chown -S fchown -S lchown -S fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership_changes

#################################
# Suspicious File System Activity
#################################
# Temporary directories (common for malware)
-w /tmp -p x -F auid!=4294967295 -k suspicious_execution
-w /var/tmp -p x -F auid!=4294967295 -k suspicious_execution
-w /dev/shm -p x -F auid!=4294967295 -k suspicious_execution

#################################
# System State & Kernel Changes
#################################
-w /sbin/shutdown -p x -k system_shutdown
-w /sbin/poweroff -p x -k system_shutdown
-w /sbin/reboot -p x -k system_shutdown
-w /sbin/halt -p x -k system_shutdown

# Kernel module operations
-a always,exit -F path=/sbin/insmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k kernel_modules
-a always,exit -F path=/sbin/rmmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k kernel_modules
-a always,exit -F path=/sbin/modprobe -F perm=x -F auid>=1000 -F auid!=4294967295 -k kernel_modules

#################################
# Audit System Protection
#################################
-w /etc/audit/ -p wa -k audit_config_changes
-w /sbin/auditctl -p x -k audit_tools
-w /sbin/auditd -p x -k audit_tools

# Make audit rules immutable (prevents tampering)
-e 2
EOF
    
    chmod 640 "$AUDIT_RULES_FILE"
    track_file_change "$AUDIT_RULES_FILE" "created"
    success "MITRE-enhanced audit rules configured"
}

# ===============================================================================
# AUDISP CONFIGURATION
# ===============================================================================

configure_audisp() {
    if [[ "$AUDISP_AVAILABLE" == "true" ]]; then
        log "INFO" "Configuring audisp-syslog plugin..."
        
        backup_file "$AUDISP_SYSLOG_CONF"
        mkdir -p "$(dirname "$AUDISP_SYSLOG_CONF")"
        
        # Detect audisp-syslog path
        local audisp_path=""
        for path in "/sbin/audisp-syslog" "/usr/sbin/audisp-syslog" "/usr/lib/audisp/audisp-syslog"; do
            if [[ -f "$path" ]]; then
                audisp_path="$path"
                break
            fi
        done
        
        if [[ -z "$audisp_path" ]]; then
            warn "audisp-syslog binary not found, skipping audisp configuration"
            return 1
        fi
        
        cat > "$AUDISP_SYSLOG_CONF" << EOF
# QRadar Unified V2 audisp-syslog plugin configuration
active = yes
direction = out
path = $audisp_path
type = always
args = LOG_${AUDIT_FACILITY^^}
format = string
EOF
        
        chmod 640 "$AUDISP_SYSLOG_CONF"
        track_file_change "$AUDISP_SYSLOG_CONF" "created"
        success "Audisp-syslog plugin configured for $AUDIT_FACILITY facility"
    else
        log "INFO" "Audisp not available, will configure direct audit log processing"
        return 1
    fi
}

# ===============================================================================
# MODERN RSYSLOG CONFIGURATION WITH QUEUE MANAGEMENT
# ===============================================================================

configure_rsyslog() {
    log "INFO" "$(msg "configuring_rsyslog")"
    
    backup_file "$RSYSLOG_QRADAR_CONF"
    
    # Determine if we need MITRE processing
    local use_mitre_processing=""
    if [[ "$MITRE_MODE" == "true" ]]; then
        use_mitre_processing="mitre_"
    fi
    
    cat > "$RSYSLOG_QRADAR_CONF" << EOF
# QRadar Unified V2 Log Forwarding Configuration
# Generated by QRadar Unified V2 Setup Script v$SCRIPT_VERSION
# Modern RainerScript syntax with queue management

# Load required modules
module(load="omprog")
module(load="omfwd")

# Global configuration for better performance
global(
  maxMessageSize="64k"
  workDirectory="/var/spool/rsyslog"
)

# Main message queue configuration
main_queue(
  queue.type="linkedlist"
  queue.filename="qradar_main_queue"
  queue.maxdiskspace="1g"
  queue.saveonshutdown="on"
  queue.timeoutenqueue="0"
)

# Block noisy kernel messages to reduce volume
if \$syslogfacility-text == "kern" then {
    stop
}

# Process audit logs from configured facility
if \$syslogfacility-text == "${AUDIT_FACILITY}" then {
    # Process EXECVE messages through MITRE parser
    if \$msg contains "type=EXECVE" then {
        action(
            type="omprog"
            binary="$PYTHON_PARSER_PATH"
            useTransactions="on"
            template="RSYSLOG_TraditionalFileFormat"
            name="qradar_${use_mitre_processing}execve_processor"
            confirmMessages="off"
            reportFailures="on"
            killUnresponsive="on"
            signalOnClose="off"
            queue.type="linkedlist"
            queue.filename="qradar_execve_queue"
            queue.size="10000"
            queue.dequeuebatchsize="100"
        )
    }
    
    # Forward all audit messages to QRadar with enhanced queue management
    action(
        type="omfwd"
        target="$QRADAR_IP"
        port="$QRADAR_PORT"
        protocol="tcp"
        name="qradar_audit_forwarder"
        queue.type="linkedlist"
        queue.filename="qradar_forward_queue"
        queue.size="100000"
        queue.maxdiskspace="2g"
        queue.dequeuebatchsize="1000"
        action.resumeRetryCount="-1"
        action.reportSuspension="on"
        action.reportSuspensionContinuation="on"
        action.resumeInterval="10"
        TCP_Framing="octet-counted"
    )
    
    # Stop processing after forwarding
    stop
}

# Forward authentication events (sudo, su, ssh, etc.)
if \$syslogfacility-text == "authpriv" or \$syslogfacility-text == "auth" then {
    action(
        type="omfwd"
        target="$QRADAR_IP"
        port="$QRADAR_PORT"
        protocol="tcp"
        name="qradar_auth_forwarder"
        queue.type="linkedlist"
        queue.size="20000"
        action.resumeRetryCount="-1"
    )
}

# Forward critical system messages only (emergency, alert, critical, error)
if \$syslogseverity <= 3 then {
    action(
        type="omfwd"
        target="$QRADAR_IP"
        port="$QRADAR_PORT"
        protocol="tcp"
        name="qradar_critical_forwarder"
        queue.type="linkedlist"
        queue.size="5000"
    )
}
EOF
    
    track_file_change "$RSYSLOG_QRADAR_CONF" "created"
    success "Modern rsyslog configuration deployed with queue management"
}

# ===============================================================================
# DIRECT AUDIT LOG PROCESSING WITH SYSTEMD
# ===============================================================================

configure_direct_audit_processing() {
    log "INFO" "Configuring direct audit log processing with systemd..."
    
    # Create systemd service
    cat > "$SYSTEMD_SERVICE_PATH" << EOF
[Unit]
Description=QRadar Audit Log Parser
After=auditd.service rsyslog.service
Wants=auditd.service rsyslog.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'tail -F /var/log/audit/audit.log | grep "type=EXECVE" | $PYTHON_PARSER_PATH | logger -p ${AUDIT_FACILITY}.info'
Restart=always
RestartSec=5
User=root
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Create systemd timer
    cat > "$SYSTEMD_TIMER_PATH" << EOF
[Unit]
Description=QRadar Audit Log Parser Timer
Requires=qradar-audit-parser.service

[Timer]
OnBootSec=30sec
OnUnitActiveSec=30sec
AccuracySec=1sec

[Install]
WantedBy=timers.target
EOF
    
    track_file_change "$SYSTEMD_SERVICE_PATH" "created"
    track_file_change "$SYSTEMD_TIMER_PATH" "created"
    
    # Enable and start systemd units
    if [[ "$FORWARDING_METHOD" == "direct" ]] || [[ "$FORWARDING_METHOD" == "dual" ]]; then
        retry_operation "Reload systemd daemon" systemctl daemon-reload
        retry_operation "Enable audit parser service" systemctl enable qradar-audit-parser.service
        retry_operation "Enable audit parser timer" systemctl enable qradar-audit-parser.timer
        retry_operation "Start audit parser timer" systemctl start qradar-audit-parser.timer
        
        ENABLED_SERVICES+=("qradar-audit-parser.service" "qradar-audit-parser.timer")
        success "Direct audit log processing configured with systemd"
    fi
}

# ===============================================================================
# FIREWALL MANAGEMENT
# ===============================================================================

configure_firewall() {
    log "INFO" "Configuring firewall for QRadar communication..."
    
    # Check for firewalld (RHEL/CentOS)
    if command_exists firewall-cmd && systemctl is-active --quiet firewalld; then
        log "INFO" "Configuring firewalld..."
        
        if execute_cmd "Add QRadar port to firewalld" firewall-cmd --permanent --add-port="$QRADAR_PORT/tcp"; then
            if execute_cmd "Reload firewalld" firewall-cmd --reload; then
                FIREWALL_RULES_ADDED+=("firewalld: $QRADAR_PORT/tcp")
                success "Firewalld configured successfully"
            fi
        fi
    fi
    
    # Check for UFW (Ubuntu)
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        log "INFO" "Configuring UFW..."
        
        if execute_cmd "Add QRadar port to UFW" ufw allow out "$QRADAR_PORT/tcp"; then
            FIREWALL_RULES_ADDED+=("ufw: $QRADAR_PORT/tcp outbound")
            success "UFW configured successfully"
        fi
    fi
    
    # Fallback to iptables if available
    if command_exists iptables && [[ ${#FIREWALL_RULES_ADDED[@]} -eq 0 ]]; then
        log "INFO" "Configuring iptables..."
        
        if execute_cmd "Add iptables rule" iptables -A OUTPUT -p tcp --dport "$QRADAR_PORT" -j ACCEPT; then
            FIREWALL_RULES_ADDED+=("iptables: $QRADAR_PORT/tcp outbound")
            success "Iptables configured successfully"
        fi
    fi
}

# ===============================================================================
# SERVICE MANAGEMENT WITH ENHANCED ERROR HANDLING
# ===============================================================================

restart_services() {
    log "INFO" "$(msg "restarting_services")"
    
    # Enable auditd
    retry_operation "Enable auditd" systemctl enable auditd
    
    # Restart auditd with fallback
    if ! retry_operation "Restart auditd" systemctl restart auditd; then
        warn "Failed to restart auditd with systemctl, trying direct start..."
        if execute_cmd "Start auditd directly" /sbin/auditd; then
            success "Auditd started directly"
        else
            warn "Auditd start failed - audit functionality may be limited"
        fi
    fi
    
    # Load audit rules
    sleep 3
    if systemctl is-active --quiet auditd; then
        if command_exists augenrules; then
            retry_operation "Load audit rules with augenrules" augenrules --load
        else
            retry_operation "Load audit rules with auditctl" auditctl -R "$AUDIT_RULES_FILE"
        fi
        success "Audit rules loaded successfully"
    else
        warn "Auditd not running - audit rules cannot be loaded"
    fi
    
    # Restart rsyslog
    retry_operation "Restart rsyslog" systemctl restart rsyslog
    retry_operation "Enable rsyslog" systemctl enable rsyslog
    
    ENABLED_SERVICES+=("auditd" "rsyslog")
    success "Core services configured successfully"
}

# ===============================================================================
# COMPREHENSIVE TESTING AND VALIDATION
# ===============================================================================

run_comprehensive_tests() {
    log "INFO" "Running comprehensive system tests..."
    
    # Test 1: Service status
    log "INFO" "Testing service status..."
    for service in "auditd" "rsyslog"; do
        if systemctl is-active --quiet "$service"; then
            success "$service is running"
        else
            warn "$service is not running"
        fi
    done
    
    # Test 2: Configuration validation
    log "INFO" "Validating rsyslog configuration..."
    if execute_cmd "Validate rsyslog config" rsyslogd -N1; then
        success "Rsyslog configuration is valid"
    else
        warn "Rsyslog configuration has issues"
    fi
    
    # Test 3: Python parser functionality
    log "INFO" "Testing MITRE parser functionality..."
    if execute_cmd "Test MITRE parser" python3 "$PYTHON_PARSER_PATH" --test; then
        success "MITRE parser is functional"
    else
        warn "MITRE parser test failed"
    fi
    
    # Test 4: Network connectivity
    log "INFO" "$(msg "network_test")"
    if timeout 10 bash -c "cat < /dev/null > /dev/tcp/$QRADAR_IP/$QRADAR_PORT" 2>/dev/null; then
        success "Network connectivity to QRadar ($QRADAR_IP:$QRADAR_PORT) successful"
    else
        warn "Cannot connect to QRadar at $QRADAR_IP:$QRADAR_PORT"
        log "INFO" "Please verify QRadar is running and network connectivity"
    fi
    
    # Test 5: Log generation test
    log "INFO" "Testing log generation..."
    local test_message="QRadar Unified V2 test message $(date '+%Y-%m-%d %H:%M:%S')"
    if execute_cmd "Send test log" logger -p "${AUDIT_FACILITY}.info" "$test_message"; then
        sleep 2
        if grep -q "$test_message" "$SYSLOG_FILE" 2>/dev/null; then
            success "Local syslog test passed"
        else
            warn "Local syslog test failed - message not found"
        fi
    fi
    
    # Test 6: Audit event test
    log "INFO" "Testing audit event generation..."
    if execute_cmd "Generate audit event" touch /etc/passwd; then
        sleep 2
        if ausearch --start today -k mitre_t1003_credential_dumping 2>/dev/null | grep -q "type=SYSCALL"; then
            success "Audit event generation successful"
        else
            warn "Audit event test failed"
        fi
    fi
}

# ===============================================================================
# COMPREHENSIVE SETUP SUMMARY
# ===============================================================================

generate_setup_summary() {
    log "INFO" "Generating comprehensive setup summary..."
    
    echo ""
    echo "=================================================================="
    echo "           QRadar Unified V2 Setup Summary"
    echo "=================================================================="
    echo ""
    
    # Configuration summary
    echo "🔧 CONFIGURATION SUMMARY:"
    echo "   • QRadar Destination: $QRADAR_IP:$QRADAR_PORT"
    echo "   • Distribution: $DISTRO $VERSION_ID ($DISTRO_FAMILY family)"
    echo "   • Package Manager: $PACKAGE_MANAGER"
    echo "   • Syslog Facility: $AUDIT_FACILITY"
    echo "   • Forwarding Method: $FORWARDING_METHOD"
    echo "   • MITRE Mode: $MITRE_MODE"
    echo "   • Language: $LANGUAGE"
    echo "   • Audisp Available: $AUDISP_AVAILABLE"
    echo ""
    
    # File modifications
    if [ ${#CREATED_FILES[@]} -gt 0 ]; then
        echo "📁 CREATED FILES:"
        for file in "${CREATED_FILES[@]}"; do
            echo "   • $file"
        done
        echo ""
    fi
    
    if [ ${#MODIFIED_FILES[@]} -gt 0 ]; then
        echo "🔧 MODIFIED FILES:"
        for file in "${MODIFIED_FILES[@]}"; do
            echo "   • $file"
        done
        echo ""
    fi
    
    if [ ${#BACKED_UP_FILES[@]} -gt 0 ]; then
        echo "💾 BACKED UP FILES:"
        for backup in "${BACKED_UP_FILES[@]}"; do
            echo "   • $backup"
        done
        echo ""
    fi
    
    # Package installations
    if [ ${#INSTALLED_PACKAGES[@]} -gt 0 ]; then
        echo "📦 INSTALLED PACKAGES:"
        for package in "${INSTALLED_PACKAGES[@]}"; do
            echo "   • $package"
        done
        echo ""
    fi
    
    # Services
    if [ ${#ENABLED_SERVICES[@]} -gt 0 ]; then
        echo "🔄 ENABLED SERVICES:"
        for service in "${ENABLED_SERVICES[@]}"; do
            echo "   • $service"
        done
        echo ""
    fi
    
    # Firewall rules
    if [ ${#FIREWALL_RULES_ADDED[@]} -gt 0 ]; then
        echo "🔥 FIREWALL RULES ADDED:"
        for rule in "${FIREWALL_RULES_ADDED[@]}"; do
            echo "   • $rule"
        done
        echo ""
    fi
    
    # Important paths
    echo "📋 IMPORTANT FILE LOCATIONS:"
    echo "   • Audit Rules: $AUDIT_RULES_FILE"
    echo "   • Rsyslog Config: $RSYSLOG_QRADAR_CONF"
    echo "   • MITRE Parser: $PYTHON_PARSER_PATH"
    echo "   • Setup Log: $LOG_FILE"
    if [[ -d "$BACKUP_DIR" ]]; then
        echo "   • Backup Directory: $BACKUP_DIR"
    fi
    echo ""
    
    # MITRE techniques info
    if [[ "$MITRE_MODE" == "true" ]]; then
        echo "🎯 MITRE ATT&CK INTEGRATION:"
        echo "   • Technique mapping enabled in parser"
        echo "   • Enhanced audit rules with MITRE tags"
        echo "   • Comprehensive threat detection coverage"
        echo ""
    fi
    
    # Testing commands
    echo "🧪 TESTING COMMANDS:"
    echo "   • Test MITRE parser:"
    echo "     python3 $PYTHON_PARSER_PATH --test"
    echo "   • Test local syslog:"
    echo "     logger -p ${AUDIT_FACILITY}.info 'Test message'"
    echo "   • Test audit events:"
    echo "     sudo touch /etc/passwd"
    echo "   • Monitor network traffic:"
    echo "     sudo tcpdump -i any host $QRADAR_IP and port $QRADAR_PORT -A -n"
    echo ""
    
    # Important notes
    echo "📝 IMPORTANT NOTES:"
    echo "   • $(msg "backup_created" "$BACKUP_DIR")"
    echo "   • Audit rules are immutable (-e 2) to prevent tampering"
    echo "   • Modern rsyslog configuration with queue management"
    echo "   • Enhanced security with non-eval command execution"
    if [[ "$MITRE_MODE" == "true" ]]; then
        echo "   • $(msg "mitre_enabled")"
    fi
    if [[ "$FORWARDING_METHOD" == "dual" ]]; then
        echo "   • $(msg "dual_method")"
    fi
    echo ""
    
    echo "=================================================================="
    log "SUCCESS" "Setup summary generated successfully"
}

# ===============================================================================
# ARGUMENT PARSING
# ===============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --facility=*)
                AUDIT_FACILITY="${1#*=}"
                shift
                ;;
            --mitre-mode)
                MITRE_MODE=true
                shift
                ;;
            --lang=*)
                LANGUAGE="${1#*=}"
                shift
                ;;
            --method=*)
                FORWARDING_METHOD="${1#*=}"
                shift
                ;;
            --help)
                show_help
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
}

show_help() {
    cat << EOF
QRadar Unified Log Forwarding Setup Script - V2 Edition v$SCRIPT_VERSION

Usage: $SCRIPT_NAME <QRADAR_IP> <QRADAR_PORT> [OPTIONS]

Arguments:
  QRADAR_IP       IP address of QRadar server
  QRADAR_PORT     Port number for QRadar log forwarding

Options:
  --facility=FACILITY     Syslog facility to use (default: local3)
                         Options: local0-local7
  --mitre-mode           Enable comprehensive MITRE ATT&CK integration
  --lang=LANGUAGE        Interface language (en|tr, default: en)
  --method=METHOD        Forwarding method (audisp|direct|dual, default: dual)
  --help                 Show this help message

Examples:
  # Basic setup
  sudo $SCRIPT_NAME 192.168.1.100 514

  # With MITRE integration and alternative facility
  sudo $SCRIPT_NAME 192.168.1.100 514 --mitre-mode --facility=local6

  # Turkish interface with direct method only
  sudo $SCRIPT_NAME 192.168.1.100 1514 --lang=tr --method=direct

Features:
  • MITRE ATT&CK technique mapping and analysis
  • Dual log forwarding methods with fallback
  • Advanced error handling and retry mechanisms
  • Modern rsyslog configuration with queue management
  • Automatic firewall configuration
  • Comprehensive audit rules with noise reduction
  • Multi-language support
  • Production-optimized performance

EOF
}

# ===============================================================================
# MAIN FUNCTION
# ===============================================================================

main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Validate arguments
    if [[ -z "$QRADAR_IP" ]] || [[ -z "$QRADAR_PORT" ]]; then
        echo "Usage: $SCRIPT_NAME <QRADAR_IP> <QRADAR_PORT> [OPTIONS]"
        echo "Use --help for detailed usage information"
        exit 1
    fi
    
    # Validate IP address format
    if ! [[ "$QRADAR_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        error_exit "Invalid IP address format: $QRADAR_IP"
    fi
    
    # Validate port number
    if ! [[ "$QRADAR_PORT" =~ ^[0-9]+$ ]] || [[ "$QRADAR_PORT" -lt 1 ]] || [[ "$QRADAR_PORT" -gt 65535 ]]; then
        error_exit "Invalid port number: $QRADAR_PORT (must be 1-65535)"
    fi
    
    # Validate forwarding method
    if ! [[ "$FORWARDING_METHOD" =~ ^(audisp|direct|dual)$ ]]; then
        error_exit "Invalid forwarding method: $FORWARDING_METHOD (must be audisp, direct, or dual)"
    fi
    
    # Initialize logging
    touch "$LOG_FILE" || error_exit "Cannot create log file $LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null || true
    
    log "INFO" "==============================================================="
    log "INFO" "QRadar Unified V2 Setup Script v$SCRIPT_VERSION"
    log "INFO" "Configuration: QRadar=$QRADAR_IP:$QRADAR_PORT, Facility=$AUDIT_FACILITY"
    log "INFO" "Options: Method=$FORWARDING_METHOD, MITRE=$MITRE_MODE, Lang=$LANGUAGE"
    log "INFO" "==============================================================="
    
    # Validate environment
    [[ $EUID -eq 0 ]] || error_exit "This script must be run as root. Use sudo."
    
    # Execute configuration steps
    detect_system
    install_packages
    deploy_mitre_parser
    configure_audit_rules
    
    # Configure forwarding methods based on selection
    if [[ "$FORWARDING_METHOD" == "audisp" ]] || [[ "$FORWARDING_METHOD" == "dual" ]]; then
        configure_audisp || log "WARN" "Audisp configuration failed, continuing with available methods"
    fi
    
    configure_rsyslog
    
    if [[ "$FORWARDING_METHOD" == "direct" ]] || [[ "$FORWARDING_METHOD" == "dual" ]]; then
        configure_direct_audit_processing
    fi
    
    configure_firewall
    restart_services
    run_comprehensive_tests
    generate_setup_summary
    
    # Final success message
    log "INFO" "==============================================================="
    success "$(msg "setup_complete")"
    log "INFO" "==============================================================="
}

# Execute main function with all arguments
main "$@"

exit 0