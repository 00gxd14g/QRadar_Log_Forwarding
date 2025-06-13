#!/usr/bin/env bash
#
# QRadar Unified Log Forwarding Setup Script v3.1
# Bu betik, çoklu platform desteği ile auditd ve rsyslog'u otomatik yapılandırarak
# QRadar SIEM'e optimize edilmiş ve güvenli log iletimi sağlar.
#
# v3.1 Değişiklikleri:
# - GÜVENLİK: `eval` komutu kaldırılarak command injection riski giderildi.
# - KARARLILIK: Rsyslog yapılandırma hatasında betiğin durması sağlandı.
# - HATA AYIKLAMA: Python parser testindeki hata gizleme sorunu düzeltildi.
# - İYİLEŞTİRME: AppArmor için daha işlevsel bir kural eklendi.
#
# Özellikler:
# - Debian/Ubuntu/RHEL/CentOS/Oracle/Alma/Rocky Linux desteği
# - MITRE ATT&CK uyumlu audit kuralları
# - EXECVE komut argümanlarını birleştiren Python script
# - Kapsamlı hata yönetimi ve otomatik düzeltme
# - SELinux/AppArmor/Firewall otomatik yapılandırması
# - Gereksiz kernel/daemon loglarını filtreleme
# - Detaylı logging ve diagnostics
#
# Kullanım: sudo bash qradar_unified_setup.sh <SIEM_IP> <SIEM_PORT>
#

set -euo pipefail

# =================== GLOBAL CONFIGURATION ===================
readonly SCRIPT_VERSION="3.1"
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

# Command execution with logging.
# GÜVENLİK NOTU: Bu fonksiyon artık 'eval' kullanmaz. Komut ve argümanları doğrudan çalıştırır.
# Pipe (|) veya kompleks yönlendirme (>) içeren komutlar doğrudan çalıştırılmalıdır.
execute_cmd() {
    local description="$1"
    shift
    local cmd_str="$*"
    
    log "Executing: $cmd_str" "DEBUG"
    if "$@" >> "$LOG_FILE" 2>&1; then
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
    local description="$2"
    shift 2
    
    while [ $attempt -le $max_attempts ]; do
        if execute_cmd "$description (attempt $attempt/$max_attempts)" "$@"; then
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
                PACKAGE_MANAGER="apt-get"
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
                    PACKAGE_MANAGER="apt-get"
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
            if ! retry_operation "Package cache update" "$PACKAGE_MANAGER" update -y; then
                warn "Package cache güncellemesi başarısız, devam ediliyor..."
            fi
            
            # Install base packages
            if ! retry_operation "Base package installation" "env" "DEBIAN_FRONTEND=noninteractive" "$PACKAGE_MANAGER" install -y $base_packages; then
                error_exit "Temel paketler kurulamadı"
            fi
            
            # Try to install optional packages
            if ! execute_cmd "Extra package installation" "env" "DEBIAN_FRONTEND=noninteractive" "$PACKAGE_MANAGER" install -y $extra_packages; then
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
                    if ! execute_cmd "EPEL installation" "$PACKAGE_MANAGER" install -y epel-release; then
                        warn "EPEL repository kurulamadı"
                    fi
                fi
            fi
            
            # Install base packages
            if ! retry_operation "Base package installation" "$PACKAGE_MANAGER" install -y $base_packages; then
                error_exit "Temel paketler kurulamadı"
            fi
            
            # Try audit plugins
            if ! execute_cmd "Audit plugins installation" "$PACKAGE_MANAGER" install -y $audit_packages; then
                warn "Audit plugins kurulamadı, devam ediliyor..."
            fi
            
            # Try rsyslog-omprog if available
            if ! execute_cmd "Rsyslog omprog installation" "$PACKAGE_MANAGER" install -y rsyslog-omprog; then
                warn "rsyslog-omprog paketi bulunamadı veya kurulamadı"
            fi
            ;;
            
        *)
            error_exit "Desteklenmeyen dağıtım ailesi: $DISTRO_FAMILY"
            ;;
    esac
    
    # Verify critical packages
    local critical_packages="auditd rsyslogd python3"
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
QRadar EXECVE Argument Parser v3.1
MITRE ATT&CK uyumlu log parsing ve command reconstruction
"""

import sys
import re

class ExecveParser:
    def __init__(self):
        self.execve_pattern = re.compile(r'type=EXECVE')
        self.arg_pattern = re.compile(r'a(\d+)="([^"]*)"')
        self.hex_arg_pattern = re.compile(r'a\d+=[0-9A-Fa-f]+')
        self.syscall_pattern = re.compile(r'type=SYSCALL.*?exe="([^"]*)".*?ppid=(\d+).*?pid=(\d+).*?uid=(\d+)')
        
    def decode_hex(self, hex_str):
        """Decode hex string if it's a valid hex value"""
        try:
            # Check if it's a pure hex string
            if all(c in '0123456789abcdefABCDEF' for c in hex_str):
                return bytes.fromhex(hex_str).decode('utf-8', errors='replace')
        except (ValueError, TypeError):
            pass  # Not a valid hex string
        return hex_str

    def parse_execve_line(self, line):
        """Parse EXECVE line and reconstruct command"""
        if not self.execve_pattern.search(line):
            return line
            
        try:
            # Extract all arguments (quoted and hex)
            args = {}
            # Quoted arguments
            for match in self.arg_pattern.finditer(line):
                arg_num = int(match.group(1))
                arg_value = match.group(2)
                args[arg_num] = arg_value

            # Hex-encoded arguments
            for match in self.hex_arg_pattern.finditer(line):
                key_val = match.group(0)
                key, hex_val = key_val.split('=', 1)
                arg_num = int(key[1:])
                # Only process if not already found as a quoted arg
                if arg_num not in args:
                    args[arg_num] = self.decode_hex(hex_val)

            if not args:
                return line
                
            # Reconstruct command from arguments
            command_parts = []
            for i in sorted(args.keys()):
                if args[i]:
                    command_parts.append(args[i])
            
            if not command_parts:
                return line
                
            full_command = ' '.join(command_parts)
            
            # Remove all existing aX= fields
            cleaned_line = self.arg_pattern.sub('', line)
            cleaned_line = self.hex_arg_pattern.sub('', cleaned_line).strip().replace('  ', ' ')
            
            if cleaned_line and not cleaned_line.endswith(' '):
                cleaned_line += ' '
                
            enhanced_line = cleaned_line + f'command="{full_command}"'
            
            mitre_tags = self.analyze_mitre_techniques(full_command, command_parts[0] if command_parts else "")
            if mitre_tags:
                enhanced_line += f' mitre_techniques="{",".join(sorted(list(set(techniques))))}"'
            
            return enhanced_line
            
        except Exception as e:
            print(f"EXECVE_PARSER_ERROR: {str(e)}", file=sys.stderr)
            return line
    
    def analyze_mitre_techniques(self, full_command, executable):
        """Analyze command for MITRE ATT&CK technique indicators"""
        techniques = []
        
        if any(tool in executable.lower() for tool in ['wget', 'curl', 'nc', 'netcat', 'ncat']):
            techniques.append('T1105')
            
        if any(cmd in full_command.lower() for cmd in ['ps ', 'netstat', 'ss ', 'lsof', 'who', 'w ', 'id ', 'whoami']):
            techniques.append('T1057')
            techniques.append('T1049')
            
        if any(path in full_command for path in ['/etc/passwd', '/etc/shadow', '/etc/group']):
            techniques.append('T1003')
            
        if any(cmd in full_command.lower() for cmd in ['crontab', 'systemctl', 'service ']):
            techniques.append('T1053')
            
        if executable.lower() in ['su', 'sudo', 'pkexec']:
            techniques.append('T1548')
            
        if any(cmd in full_command.lower() for cmd in ['chmod +x', 'chattr', 'rm ', 'unlink']):
            techniques.append('T1222')
            
        if any(interpreter in executable.lower() for interpreter in ['python', 'perl', 'ruby', 'node', 'bash', 'sh']):
            techniques.append('T1059')
            
        return sorted(list(set(techniques)))

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
    
    chmod 755 "$PYTHON_SCRIPT_PATH" || error_exit "Python script izinleri ayarlanamadı"
    chown root:root "$PYTHON_SCRIPT_PATH" 2>/dev/null || warn "Python script sahipliği ayarlanamadı"
    
    if ! python3 -m py_compile "$PYTHON_SCRIPT_PATH" 2>/dev/null; then
        error_exit "Python script syntax hatası"
    fi
    
    success "Python EXECVE parser deployed successfully"
}

# =================== AUDIT CONFIGURATION ===================

configure_auditd() {
    log "Configuring auditd with MITRE ATT&CK aligned rules..." "INFO"
    
    if [ -f "$AUDIT_RULES_FILE" ]; then
        cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.$BACKUP_SUFFIX" 2>/dev/null || \
            warn "Mevcut audit kuralları yedeklenemedi"
    fi
    
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")" || error_exit "Audit rules dizini oluşturulamadı"
    
    cat > "$AUDIT_RULES_FILE" << 'AUDIT_RULES_EOF'
# QRadar MITRE ATT&CK Aligned Audit Rules v3.1
# Generated automatically - do not edit manually

# Delete all existing rules and set configuration
-D
-b 8192
-f 1
-a always,exit -F arch=b64 -S execve -k mitre_execve
-a always,exit -F arch=b32 -S execve -k mitre_execve

##########################################
# MITRE ATT&CK: TA0003 - Persistence
##########################################
-w /etc/crontab -p wa -k mitre_t1053_cron
-w /etc/cron.d/ -p wa -k mitre_t1053_cron
-w /var/spool/cron/ -p wa -k mitre_t1053_cron
-w /etc/systemd/system/ -p wa -k mitre_t1543_systemd
-w /etc/init.d/ -p wa -k mitre_t1543_init

##########################################
# MITRE ATT&CK: TA0004 - Privilege Escalation
##########################################
-w /etc/sudoers -p wa -k mitre_t1548_sudoers
-w /etc/sudoers.d/ -p wa -k mitre_t1548_sudoers
-a always,exit -F arch=b64 -S setuid -S setgid -S seteuid -S setegid -k mitre_t1548_setuid
-a always,exit -F arch=b32 -S setuid -S setgid -S seteuid -S setegid -k mitre_t1548_setuid

##########################################
# MITRE ATT&CK: TA0005 - Defense Evasion
##########################################
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k mitre_t1222_chmod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k mitre_t1222_chmod
-w /var/log/ -p wa -k mitre_t1070_log_manipulation
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k mitre_t1070_file_deletion
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k mitre_t1070_file_deletion

##########################################
# MITRE ATT&CK: TA0006 - Credential Access
##########################################
-w /etc/passwd -p rwa -k mitre_t1003_credential_files
-w /etc/shadow -p rwa -k mitre_t1003_credential_files
-w /etc/gshadow -p rwa -k mitre_t1003_credential_files
-w /root/.ssh/ -p rwa -k mitre_t1552_ssh_keys

##########################################
# System Administration and Security
##########################################
-w /etc/audit/ -p wa -k audit_config_modification
-w /etc/pam.d/ -p wa -k pam_modification
-w /etc/ssh/sshd_config -p wa -k ssh_config_modification
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config_modification
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_config_modification
-w /etc/hosts -p wa -k network_config_modification
-a always,exit -F arch=b64 -S mount -k mitre_t1562_mount
-a always,exit -F arch=b32 -S mount -k mitre_t1562_mount

# Make configuration immutable (HIGHLY recommended for production servers)
# -e 2
AUDIT_RULES_EOF

    chmod 640 "$AUDIT_RULES_FILE" || error_exit "Audit rules dosyası izinleri ayarlanamadı"
    configure_audisp_plugin
    load_audit_rules
    success "Auditd configuration completed"
}

configure_audisp_plugin() {
    log "Configuring audisp-syslog plugin..." "INFO"
    
    local audisp_binary="/sbin/audisp-syslog"
    if [ ! -x "$audisp_binary" ]; then
        audisp_binary="/usr/sbin/audisp-syslog"
        if [ ! -x "$audisp_binary" ]; then
            warn "audisp-syslog binary bulunamadı. Plugin yapılandırması atlanıyor."
            return 0
        fi
    fi
    
    mkdir -p "$(dirname "$AUDISP_PLUGIN_CONF")" || warn "Audisp config dizini oluşturulamadı"
    
    if [ -f "$AUDISP_PLUGIN_CONF" ]; then
        cp "$AUDISP_PLUGIN_CONF" "${AUDISP_PLUGIN_CONF}.$BACKUP_SUFFIX" 2>/dev/null || \
            warn "Mevcut audisp config yedeklenemedi"
    fi
    
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
    
    retry_operation "Enable auditd service" systemctl enable auditd
    
    if command -v augenrules >/dev/null 2>&1; then
        if ! retry_operation "Load audit rules with augenrules" augenrules --load; then
            warn "augenrules ile kural yüklemesi başarısız, auditctl deneniyor..."
            if ! retry_operation "Load audit rules with auditctl" auditctl -R "$AUDIT_RULES_FILE"; then
                warn "Audit kuralları yüklenemedi"
            fi
        fi
    else
        if ! retry_operation "Load audit rules with auditctl" auditctl -R "$AUDIT_RULES_FILE"; then
            warn "Audit kuralları yüklenemedi"
        fi
    fi
    
    if ! retry_operation "Restart auditd service" systemctl restart auditd; then
        warn "auditd servisi yeniden başlatılamadı"
    fi
    sleep 3
    
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
    
    if [ -f "$RSYSLOG_SIEM_CONF" ]; then
        cp "$RSYSLOG_SIEM_CONF" "${RSYSLOG_SIEM_CONF}.$BACKUP_SUFFIX" 2>/dev/null || \
            warn "Mevcut rsyslog config yedeklenemedi"
    fi
    
    cat > "$RSYSLOG_SIEM_CONF" << EOF
# QRadar SIEM Forwarding Configuration v3.1
# Automatically generated - manual edits will be lost

module(load="omprog")

\$WorkDirectory /var/spool/rsyslog
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
\$ActionQueueType LinkedList
\$ActionQueueFileName qradar_queue
\$ActionQueueMaxDiskSpace 1g
\$ActionQueueSaveOnShutdown on
\$ActionQueueSize 100000
\$ActionResumeRetryCount -1

# Block noisy kernel/daemon messages
if \$syslogfacility-text == "kern" or \$syslogfacility-text == "daemon" then {
    stop
}

# Process audit logs from $AUDIT_FACILITY facility
if \$syslogfacility-text == "$AUDIT_FACILITY" then {
    # Transform EXECVE messages with Python parser
    if \$msg contains "type=EXECVE" then {
        action(
            type="omprog"
            binary="$PYTHON_SCRIPT_PATH"
            name="QRadarExecveParser"
            useTransactions="off"
            confirmMessages="off"
            reportFailures="on"
            closeTimeout="5000"
            output="/var/log/qradar_execve_parser.log"
        )
    }
    
    # Forward all audit events to QRadar SIEM
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
        action.resumeRetryCount="-1"
    )
    stop
}

# Forward critical authentication logs regardless of facility
if (
    \$programname == "sshd" or
    \$programname == "sudo" or
    \$programname == "su" or
    \$programname == "login" or
    \$msg contains "authentication failure" or
    \$msg contains "password check failed" or
    \$msg contains "session opened" or
    \$msg contains "session closed"
) then {
    action(
        type="omfwd"
        target="$siem_ip"
        port="$siem_port"
        protocol="tcp"
        name="QRadarAuthForwarder"
    )
}
EOF

    validate_rsyslog_config
    
    if ! retry_operation "Enable rsyslog service" systemctl enable rsyslog; then
        warn "rsyslog servisi enable edilemedi"
    fi
    
    if ! retry_operation "Restart rsyslog service" systemctl restart rsyslog; then
        error_exit "rsyslog servisi yeniden başlatılamadı"
    fi
    
    sleep 3
    success "Rsyslog configuration completed"
}

validate_rsyslog_config() {
    log "Validating rsyslog configuration..." "INFO"
    
    local validation_output
    validation_output=$(rsyslogd -N1 2>&1)
    local validation_result=$?
    
    if [ $validation_result -eq 0 ]; then
        log "Rsyslog configuration validation passed" "INFO"
    else
        warn "Rsyslog configuration validation reported issues."
        echo "$validation_output" >> "$LOG_FILE"
        
        if echo "$validation_output" | grep -qi "error"; then
            error_exit "Rsyslog configuration has critical errors. Aborting setup."
        else
            log "Continuing despite validation warnings..." "INFO"
        fi
    fi
}

# =================== OS-SPECIFIC CONFIGURATIONS ===================

configure_os_specifics() {
    log "Configuring OS-specific settings..." "INFO"
    
    case "$DISTRO_FAMILY" in
        rhel)
            configure_rhel_specifics "$2"
            ;;
        debian)
            configure_debian_specifics "$2"
            ;;
    esac
    
    success "OS-specific configuration completed"
}

configure_rhel_specifics() {
    local siem_port="$1"
    log "Applying RHEL-specific configurations..." "INFO"
    configure_selinux
    configure_firewall "$siem_port"
}

configure_selinux() {
    if ! command -v getenforce >/dev/null 2>&1; then
        log "SELinux tools not found, skipping SELinux configuration" "INFO"
        return 0
    fi
    
    if [ "$(getenforce)" = "Enforcing" ]; then
        log "SELinux is Enforcing. Applying policies..." "INFO"
        execute_cmd "Enable rsyslog network connections" setsebool -P syslogd_can_network_connect on
        if [ -f "$PYTHON_SCRIPT_PATH" ]; then
            execute_cmd "Set SELinux context for Python script" chcon -t syslogd_script_exec_t "$PYTHON_SCRIPT_PATH"
        fi
    fi
}

configure_firewall() {
    local siem_port="$1"
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        log "Configuring firewalld for SIEM port $siem_port..." "INFO"
        execute_cmd "Add firewall rule for SIEM port" firewall-cmd --permanent --add-port="$siem_port/tcp"
        execute_cmd "Reload firewall rules" firewall-cmd --reload
    else
        log "Firewalld not active, skipping firewall configuration" "INFO"
    fi
}

configure_debian_specifics() {
    local siem_port="$1"
    log "Applying Debian-specific configurations..." "INFO"
    
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        log "UFW detected, adding rule for SIEM port $siem_port..." "INFO"
        execute_cmd "Add UFW rule for SIEM" ufw allow out to any port "$siem_port" proto tcp
    fi
    
    if command -v aa-status >/dev/null 2>&1 && aa-status --enabled; then
        log "AppArmor detected, checking profiles..." "INFO"
        local apparmor_local_profile="/etc/apparmor.d/local/usr.sbin.rsyslogd"
        if [ -d /etc/apparmor.d/local ]; then
             if ! grep -q "$PYTHON_SCRIPT_PATH" "$apparmor_local_profile" 2>/dev/null; then
                log "Adding AppArmor exception for Python script..." "INFO"
                echo "# QRadar script exception" >> "$apparmor_local_profile"
                echo "  $PYTHON_SCRIPT_PATH ix," >> "$apparmor_local_profile"
                execute_cmd "Reload AppArmor profiles" systemctl reload apparmor || warn "AppArmor profilleri yeniden yüklenemedi"
            fi
        fi
    fi
}

# =================== TESTING AND VALIDATION ===================

run_comprehensive_tests() {
    local siem_ip="$1"
    local siem_port="$2"
    log "Running comprehensive system tests..." "INFO"
    
    test_services
    test_audit_rules
    test_python_script
    test_network_connectivity "$siem_ip" "$siem_port"
    test_log_forwarding "$siem_ip" "$siem_port"
    
    success "Comprehensive testing completed"
}

test_services() {
    log "Testing service status..." "INFO"
    for service in auditd rsyslog; do
        if systemctl is-active --quiet "$service"; then
            log "Service $service is active and running" "INFO"
        else
            warn "Service $service is not active. Attempting to start..."
            execute_cmd "Start $service service" systemctl start "$service"
        fi
    done
}

test_audit_rules() {
    log "Testing audit rules..." "INFO"
    if command -v auditctl >/dev/null 2>&1; then
        local rule_count
        rule_count=$(auditctl -l 2>/dev/null | wc -l)
        if [ "$rule_count" -gt 5 ]; then # Check for a reasonable number of rules
            log "Audit rules active: $rule_count rules loaded" "INFO"
            local mitre_rules
            mitre_rules=$(auditctl -l 2>/dev/null | grep -c "mitre_" || echo "0")
            log "MITRE ATT&CK rules loaded: $mitre_rules" "INFO"
        else
            warn "No audit rules or very few rules are currently loaded."
        fi
    fi
}

test_python_script() {
    log "Testing Python EXECVE parser..." "INFO"
    if [ ! -x "$PYTHON_SCRIPT_PATH" ]; then
        warn "Python script is not executable: $PYTHON_SCRIPT_PATH"
        return 1
    fi
    
    local test_input='type=EXECVE msg=audit(1678886400.123:456): argc=3 a0="ls" a1="-la" a2="/tmp"'
    local test_output_and_error
    test_output_and_error=$(echo "$test_input" | "$PYTHON_SCRIPT_PATH" 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ] && echo "$test_output_and_error" | grep -q 'command="ls -la /tmp"'; then
        log "Python EXECVE parser test successful" "INFO"
    else
        warn "Python EXECVE parser test failed (exit code: $exit_code)"
        log "Test input: $test_input" "DEBUG"
        log "Test output/error: $test_output_and_error" "DEBUG"
    fi
}

test_network_connectivity() {
    local siem_ip="$1"
    local siem_port="$2"
    log "Testing network connectivity to SIEM ($siem_ip:$siem_port)..." "INFO"
    
    if command -v nc >/dev/null 2>&1; then
        if nc -z -w 5 "$siem_ip" "$siem_port"; then
            log "Network connectivity to $siem_ip:$siem_port successful" "INFO"
        else
            warn "Network connectivity to $siem_ip:$siem_port failed (using nc)."
            log "Consider checking: firewall rules (local and remote), network routing, SIEM availability" "INFO"
        fi
    elif command -v telnet >/dev/null 2>&1; then
        if echo "exit" | telnet "$siem_ip" "$siem_port" 2>/dev/null | grep -q "Connected"; then
            log "Network connectivity to $siem_ip:$siem_port successful" "INFO"
        else
            warn "Network connectivity to $siem_ip:$siem_port failed (using telnet)."
        fi
    else
        warn "No network testing tools available (nc, telnet)"
    fi
}

test_log_forwarding() {
    log "Testing log forwarding functionality..." "INFO"
    local test_message="QRadar_Test_Event_$(hostname)_$(date +%s)"
    
    log "Sending test syslog message via logger..." "INFO"
    logger -p "$AUDIT_FACILITY.info" -t "QRadarSetupTest" "$test_message" || warn "Test syslog mesajı gönderilemedi"
    
    log "Test message sent. Please check your QRadar Log Activity for an event with payload containing '$test_message' in the next 1-2 minutes." "INFO"
}

# =================== CLEANUP AND FINALIZATION ===================

cleanup_and_finalize() {
    log "Performing cleanup and finalization..." "INFO"
    
    chmod 640 "$LOG_FILE" 2>/dev/null || warn "Log dosyası izinleri ayarlanamadı"
    create_logrotate_config
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
    create 0640 root root
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
    
    echo "======================================================================"
    log "=== QRadar Unified Setup Status Report ===" "INFO"
    log "Setup Version: $SCRIPT_VERSION" "INFO"
    log "Platform: $DISTRO $VERSION_ID_NUM ($DISTRO_FAMILY)" "INFO"
    log "SIEM Target: $siem_ip:$siem_port" "INFO"
    
    log "--- Service Status ---" "INFO"
    for service in auditd rsyslog; do
        if systemctl is-active --quiet "$service"; then
            log "$service: ACTIVE" "INFO"
        else
            log "$service: INACTIVE" "ERROR"
        fi
    done
    
    log "--- Configuration Files ---" "INFO"
    for file in "$PYTHON_SCRIPT_PATH" "$AUDIT_RULES_FILE" "$RSYSLOG_SIEM_CONF"; do
        [ -f "$file" ] && log "$file: EXISTS" "INFO" || log "$file: MISSING" "ERROR"
    done
    
    log "=== Next Steps ===" "INFO"
    log "1. QRadar SIEM sunucusunda '$siem_ip' için bir Log Source oluşturulduğundan emin olun." "INFO"
    log "2. QRadar Log Activity arayüzünde bu sunucudan gelen logları kontrol edin." "INFO"
    log "3. Ağ trafiğini anlık izlemek için: tcpdump -i any host $siem_ip and port $siem_port -A -n" "INFO"
    log "4. Detaylı kurulum logları için: $LOG_FILE" "INFO"
    echo "======================================================================"
}

# =================== MAIN EXECUTION ===================

main() {
    check_prerequisites "$@"
    
    local siem_ip="$1"
    local siem_port="$2"
    
    detect_platform
    install_packages
    deploy_python_script
    configure_auditd
    configure_rsyslog "$siem_ip" "$siem_port"
    configure_os_specifics "$siem_ip" "$siem_port"
    
    run_comprehensive_tests "$siem_ip" "$siem_port"
    cleanup_and_finalize "$siem_ip" "$siem_port"
    
    log "QRadar Unified Log Forwarding Setup completed successfully!" "SUCCESS"
}

# Execute main function with all arguments
main "$@"
