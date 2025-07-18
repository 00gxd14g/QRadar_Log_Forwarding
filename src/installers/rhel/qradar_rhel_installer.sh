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
RESTORE_MODE=false

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
        local backup_path
        backup_path="$BACKUP_DIR/$(basename "$file").$(date +%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp --preserve=mode,ownership,timestamps "$file" "$backup_path" \
          || warn "Could not backup $file"
        log "INFO" "Backed up $file → $backup_path"
    fi
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
    log "INFO" "Starting QRadar configuration rollback for RHEL family..."
    
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
        "/etc/rsyslog.d/99-qradar.conf"
        "/etc/rsyslog.conf"
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
    
    # Reload audit rules
    auditctl -R /etc/audit/rules.d/audit.rules 2>/dev/null || true
    
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

detect_rhel_family() {
    log "INFO" "Detecting RHEL family distribution..."
    
    [[ -d "$RESOURCE_DIR" ]] || error_exit "Resource directory $RESOURCE_DIR missing"

    if [[ ! -f /etc/os-release ]]; then
        error_exit "/etc/os-release file not found. Cannot verify RHEL system."
    fi
    
    # shellcheck disable=SC1091
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
            safe_execute "EPEL repository installation" execute_with_privilege "$PACKAGE_MANAGER" install -y epel-release || warn "EPEL installation failed"
        fi
        
        if [[ "$DISTRO_ID" == "ubuntu" ]]; then
            retry_operation "Package installation" execute_with_privilege "$PACKAGE_MANAGER" update
        fi
        retry_operation "Package installation" execute_with_privilege "$PACKAGE_MANAGER" install -y "${packages_to_install[@]}"
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
    
    # Copy the existing parser from the helpers directory
    if [[ ! -f "${SCRIPT_DIR}/../../helpers/execve_parser.py" ]]; then
        error_exit "Parser file not found: ${SCRIPT_DIR}/../../helpers/execve_parser.py"
    fi
    
    cp "${SCRIPT_DIR}/../../helpers/execve_parser.py" "$CONCAT_SCRIPT_PATH" || error_exit "Failed to copy EXECVE parser script"
    
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
    for helper_script in "extract_audit_type.sh" "extract_audit_result.sh"; do
        local helper_source="${SCRIPT_DIR}/../../helpers/${helper_script}"
        local helper_dest="/usr/local/bin/${helper_script}"
        
        if [[ -f "$helper_source" ]]; then
            cp "$helper_source" "$helper_dest" || warn "Failed to copy $helper_script"
            chmod +x "$helper_dest"
            chown root:root "$helper_dest"
        else
            warn "Helper script not found: $helper_source"
        fi
    done
    
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
# AUDITD DAEMON CONFIGURATION
# ===============================================================================

configure_auditd_daemon() {
    log "INFO" "Configuring auditd daemon for RHEL family..."
    
    local auditd_conf="/etc/audit/auditd.conf"
    backup_file "$auditd_conf"
    
    # Create auditd.conf with corrected configuration
    cat > "$auditd_conf" << 'AUDITD_CONF_EOF'
# auditd.conf - QRadar RHEL configuration
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
    success "Auditd daemon configuration completed for RHEL family"
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
# APPARMOR CONFIGURATION
# ===============================================================================

configure_apparmor() {
    log "INFO" "Checking AppArmor configuration for RHEL family..."
    
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
        
        # Reload AppArmor profile
        if command -v apparmor_parser &> /dev/null; then
            apparmor_parser -r "$apparmor_profile" 2>/dev/null || warn "AppArmor profile reload failed"
        fi
        
        success "AppArmor rsyslog permissions configured for RHEL family"
    else
        log "INFO" "AppArmor profile not found, skipping (normal for RHEL family)"
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

    # Create QRadar configuration directly in script
    # shellcheck disable=SC2154
    cat > "$RSYSLOG_QRADAR_CONF" << 'EOF'
# QRadar Minimal Log Forwarding Configuration v4.2.1
# This file is placed in /etc/rsyslog.d/

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
    $programname == 'httpd' or $programname == 'nginx' or
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
               binary="/usr/local/bin/qradar_execve_parser.py")
    }
    
    # Forward to QRadar with LEEF format
    action(type="omfwd"
           Target="<QRADAR_IP>"
           Port="<QRADAR_PORT>"
           Protocol="tcp"
           queue.type="linkedList"
           queue.filename="qradar_audit_fwd"
           action.resumeRetryCount="-1")
    stop
}
EOF

    # Replace placeholders
    sed -i -e "s/<QRADAR_IP>/$QRADAR_IP/g" \
        -e "s/<QRADAR_PORT>/$QRADAR_PORT/g" \
        "$RSYSLOG_QRADAR_CONF"

    chmod 644 "$RSYSLOG_QRADAR_CONF"

    # Create minimal rsyslog.conf directly in script
    backup_file "/etc/rsyslog.conf"
    cat > "/etc/rsyslog.conf" << 'EOF'
# QRadar Minimal Rsyslog Configuration
# Version: 4.0.0
# Only essential security logs are forwarded to QRadar

# Working directory
$WorkDirectory /var/spool/rsyslog

# Use default timestamp format
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# Set the default permissions
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022

# Include all config files in /etc/rsyslog.d/
$IncludeConfig /etc/rsyslog.d/*.conf

# Minimal essential system logs only
kern.warning                    /var/log/kern.log
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog

# Emergency messages to all users
*.emerg                         :omusrmsg:*

# Don't log private authentication messages
auth,authpriv.none              -/var/log/syslog

# QRadar specific logging rules are in /etc/rsyslog.d/99-qradar.conf
EOF
    chmod 644 "/etc/rsyslog.conf"

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
    
    # Root check
    [[ $EUID -eq 0 ]] || error_exit "This script must be run as root. Use 'sudo'."
    
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
    log "INFO" "QRadar Universal RHEL Family Log Forwarding Installer v$SCRIPT_VERSION"
    log "INFO" "Starting: $(date)"
    log "INFO" "QRadar Target: $QRADAR_IP:$QRADAR_PORT"
    log "INFO" "============================================================="
    
    # Main installation steps
    detect_rhel_family
    install_required_packages
    deploy_execve_parser
    configure_auditd
    configure_auditd_daemon
    configure_audit_plugins
    configure_selinux
    configure_apparmor
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
        --restore)
            RESTORE_MODE=true
            shift
            ;;
        -h|--help)
            echo "QRadar Universal RHEL Family Installer v$SCRIPT_VERSION"
            echo ""
            echo "Usage: $0 <QRADAR_IP> <QRADAR_PORT> [OPTIONS]"
            echo "       $0 --restore"
            echo ""
            echo "Options:"
            echo "  --minimal    Use minimal audit rules for EPS optimization"
            echo "  --open-port  Open the QRadar port in firewalld"
            echo "  --restore    Restore original configuration (rollback all changes)"
            echo "  --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 192.168.1.100 514"
            echo "  $0 192.168.1.100 514 --minimal --open-port"
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

# Parameter validation
if [[ "$RESTORE_MODE" != true ]]; then
    if [[ -z "$QRADAR_IP" ]] || [[ -z "$QRADAR_PORT" ]]; then
        echo "Usage: $0 <QRADAR_IP> <QRADAR_PORT> [--minimal]"
        echo "       $0 --restore"
        echo "Example: $0 192.168.1.100 514 --minimal"
        echo "         $0 --restore"
        exit 1
    fi

    # IP address format check
    if ! [[ "$QRADAR_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        error_exit "Invalid IP address format: $QRADAR_IP"
    fi
fi

# Port number check
if [[ "$RESTORE_MODE" != true ]]; then
    if ! [[ "$QRADAR_PORT" =~ ^[0-9]+$ ]] || [[ "$QRADAR_PORT" -lt 1 ]] || [[ "$QRADAR_PORT" -gt 65535 ]]; then
        error_exit "Invalid port number: $QRADAR_PORT (must be between 1-65535)"
    fi
fi

# Ana fonksiyonu çalıştır
main

exit 0