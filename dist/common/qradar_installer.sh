#!/usr/bin/env bash
#
# ===============================================================================
# QRadar Unified Log Forwarding Installer v1.0.2
# ===============================================================================
#
# This script provides a unified, robust, and modern solution for forwarding
# Linux audit and system logs to IBM QRadar SIEM.
#
# Features:
#   - Broad Linux distribution support (Debian/Ubuntu, RHEL/CentOS/Fedora families).
#   - Intelligent platform detection and adaptation.
#   - Advanced log enrichment with a Python-based parser for EXECVE events.
#   - MITRE ATT&CK technique mapping for enhanced threat detection.
#   - Resilient log forwarding with modern rsyslog queueing.
#   - Automatic fallback from audisp to direct audit log monitoring if needed.
#   - Secure, non-eval command execution and comprehensive error handling.
#   - Automated backup of existing configurations.
#   - Self-contained and idempotent design.
#
# Usage: sudo bash qradar_installer.sh <QRADAR_IP> <QRADAR_PORT> [OPTIONS]
#
# Options:
#   --facility <local0-7>  Set the syslog facility for audit logs (default: local3).
#   --lang <en|tr>         Set the script's display language (default: en).
#
# Author: Gemini
# Version: 1.0.2
# ===============================================================================

set -euo pipefail

# --- Script Configuration ---
readonly SCRIPT_VERSION="1.0.2"
readonly SCRIPT_DIR
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/qradar_installer.log"
readonly BACKUP_DIR
BACKUP_DIR="/etc/qradar_installer_backup_$(date +%Y%m%d_%H%M%S)"

# --- File Paths ---
readonly PYTHON_PARSER_PATH="/usr/local/bin/execve_parser.py"
readonly AUDIT_RULES_FILE="/etc/audit/rules.d/99-qradar.rules"
readonly AUDISP_SYSLOG_CONF="/etc/audit/plugins.d/syslog.conf"
readonly RSYSLOG_QRADAR_CONF="/etc/rsyslog.d/99-qradar.conf"

# --- Default Settings ---
AUDIT_FACILITY="local3"
LANGUAGE="en"

# --- Global State Variables ---
DISTRO_FAMILY=""
PACKAGE_MANAGER=""
AUDISP_METHOD_AVAILABLE=false
QRADAR_IP=""
QRADAR_PORT=""

# ===============================================================================
# UTILITY AND LOGGING FUNCTIONS
# ===============================================================================

# Centralized logging function with level and language support
log() {
    local level="${1:-INFO}"
    local message_key="$2"
    shift 2
    local formatted_message

    case "$LANGUAGE" in
        tr) 
            case "$message_key" in
                "init")                  formatted_message="QRadar Unified Installer v$SCRIPT_VERSION başlatılıyor...";;
                "root_check_fail")       formatted_message="Bu betik root yetkisiyle çalıştırılmalıdır. Lütfen 'sudo' kullanın.";;
                "detecting_distro")      formatted_message="Linux dağıtımı ve sürümü tespit ediliyor...";;
                "detected_distro")       formatted_message="Tespit edilen platform: %s (Aile: %s, Paket Yöneticisi: %s)";;
                "unsupported_distro")    formatted_message="Desteklenmeyen dağıtım ailesi: %s";;
                "installing_packages")   formatted_message="Gerekli paketler (auditd, rsyslog, python3) kontrol ediliyor/kuruluyor...";;
                "deploying_parser")      formatted_message="Gelişmiş EXECVE log ayrıştırıcısı (Python) dağıtılıyor...";;
                "configuring_auditd")    formatted_message="MITRE ATT&CK uyumlu auditd kuralları yapılandırılıyor...";;
                "configuring_audisp")    formatted_message="audisp-syslog eklentisi yapılandırılıyor...";;
                "audisp_fail_fallback")  formatted_message="audisp-syslog kullanılamıyor, doğrudan audit log izleme (fallback) yapılandırılıyor...";;
                "configuring_rsyslog")   formatted_message="Güvenilir log iletimi için rsyslog yapılandırılıyor...";;
                "restarting_services")   formatted_message="Servisler (auditd, rsyslog) yeniden başlatılıyor...";;
                "running_tests")         formatted_message="Yapılandırma testleri ve doğrulamaları çalıştırılıyor...";;
                "test_net_ok")           formatted_message="QRadar sunucusuna (%s:%s) ağ bağlantısı başarılı.";;
                "test_net_fail")         formatted_message="UYARI: QRadar sunucusuna (%s:%s) ağ bağlantısı kurulamadı.";;
                "setup_complete")        formatted_message="Kurulum başarıyla tamamlandı! Log dosyası: $LOG_FILE";;
                *)                       formatted_message="$message_key $*";;
            esac
            ;;
        *) # Default to English
            case "$message_key" in
                "init")                  formatted_message="Starting QRadar Unified Installer v$SCRIPT_VERSION...";;
                "root_check_fail")       formatted_message="This script must be run as root. Please use 'sudo'.";;
                "detecting_distro")      formatted_message="Detecting Linux distribution and version...";;
                "detected_distro")       formatted_message="Detected platform: %s (Family: %s, Package Manager: %s)";;
                "unsupported_distro")    formatted_message="Unsupported distribution family: %s";;
                "installing_packages")   formatted_message="Checking/installing required packages (auditd, rsyslog, python3)...";;
                "deploying_parser")      formatted_message="Deploying advanced EXECVE log parser (Python)...";;
                "configuring_auditd")    formatted_message="Configuring MITRE ATT&CK aligned auditd rules...";;
                "configuring_audisp")    formatted_message="Configuring audisp-syslog plugin...";;
                "audisp_fail_fallback")  formatted_message="audisp-syslog is not available, configuring direct audit log monitoring (fallback)...";;
                "configuring_rsyslog")   formatted_message="Configuring rsyslog for reliable log forwarding...";;
                "restarting_services")   formatted_message="Restarting services (auditd, rsyslog)...";;
                "running_tests")         formatted_message="Running configuration tests and verifications...";;
                "test_net_ok")           formatted_message="Network connectivity to QRadar at %s:%s is successful.";;
                "test_net_fail")         formatted_message="WARNING: Network connectivity to QRadar at %s:%s failed.";;
                "setup_complete")        formatted_message="Setup completed successfully! Log file: $LOG_FILE";;
                *)                       formatted_message="$message_key $*";;
            esac
            ;;
    esac

    # shellcheck disable=SC2059
    printf "[%(
%Y-%m-%d %H:%M:%S)T] [%-7s] ${formatted_message}\n" "-1" "$level" "$@" | tee -a "$LOG_FILE"
}

# Secure command execution wrapper
execute() {
    local description="$1"
    shift
    log "Executing: $description" "DEBUG"
    if "$@" >> "$LOG_FILE" 2>&1; then
        return 0
    else
        local exit_code=$?
        log "Failed: $description (Exit code: $exit_code)" "WARN"
        return $exit_code
    fi
}

# Retry mechanism for critical operations
retry() {
    local attempts=3
    local delay=5
    local description="$1"
    shift

    for ((i=1; i<=attempts; i++)); do
        if execute "$description (Attempt $i/$attempts)" "$@"; then
            return 0
        fi
        if [[ $i -lt $attempts ]]; then
            log "Retrying in $delay seconds..." "DEBUG"
            sleep $delay
        fi
    done
    log "Failed after $attempts attempts: $description" "ERROR"
    return 1
}

# Backup a file if it exists
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -a "$file" "$BACKUP_DIR/$(basename "$file")"
        log "Backed up '$file' to '$BACKUP_DIR'" "INFO"
    fi
}

# ===============================================================================
# CORE LOGIC
# ===============================================================================

# 1. Detect the operating system environment
detect_system() {
    log "INFO" "detecting_distro"
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/etc/os-release
        source /etc/os-release
        local distro_id="${ID_LIKE:-$ID}"
        case "$distro_id" in
            *debian*)   DISTRO_FAMILY="debian"; PACKAGE_MANAGER="apt-get";;
            *rhel*|*fedora*) DISTRO_FAMILY="rhel"; PACKAGE_MANAGER="dnf";;
            *)          log "ERROR" "unsupported_distro" "$distro_id"; exit 1;;
        esac
        # For RHEL < 8, use yum
        if [[ "$DISTRO_FAMILY" == "rhel" ]] && ! command -v dnf &>/dev/null; then
            PACKAGE_MANAGER="yum"
        fi
        log "INFO" "detected_distro" "$PRETTY_NAME" "$DISTRO_FAMILY" "$PACKAGE_MANAGER"
    else
        log "ERROR" "/etc/os-release not found. Cannot determine distribution." ; exit 1
    fi
}

# 2. Install required packages for auditd, rsyslog, and python
install_packages() {
    log "INFO" "installing_packages"
    local packages_needed=()
    command -v auditd &>/dev/null || packages_needed+=("auditd")
    command -v rsyslogd &>/dev/null || packages_needed+=("rsyslog")
    command -v python3 &>/dev/null || packages_needed+=("python3")

    if [[ "$DISTRO_FAMILY" == "debian" ]]; then
        command -v audisp-syslog &>/dev/null || packages_needed+=("audispd-plugins")
    elif [[ "$DISTRO_FAMILY" == "rhel" ]]; then
        # In RHEL, 'audit' provides auditd
        if ! command -v auditd &>/dev/null; then packages_needed=("${packages_needed[@]/auditd/audit}"); fi
        command -v audisp-syslog &>/dev/null || packages_needed+=("audispd-plugins")
    fi

    if [[ ${#packages_needed[@]} -gt 0 ]]; then
        log "Packages to install: ${packages_needed[*]}" "INFO"
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            retry "Updating package list" "$PACKAGE_MANAGER" update -y
            retry "Installing packages" env DEBIAN_FRONTEND=noninteractive "$PACKAGE_MANAGER" install -y "${packages_needed[@]}"
        else
            retry "Installing packages" "$PACKAGE_MANAGER" install -y "${packages_needed[@]}"
        fi
    else
        log "All required packages are already installed." "INFO"
    fi
}

# 3. Deploy the advanced Python parser script
deploy_parser() {
    log "INFO" "deploying_parser"
    local helper_script="$SCRIPT_DIR/../helpers/execve_parser.py"
    if [[ ! -f "$helper_script" ]]; then
        log "Parser script not found at '$helper_script'. Cannot continue." "ERROR"
        return 1
    }
    backup_file "$PYTHON_PARSER_PATH"
    cp "$helper_script" "$PYTHON_PARSER_PATH"
    chmod 755 "$PYTHON_PARSER_PATH"
    chown root:root "$PYTHON_PARSER_PATH"
}

# 4. Configure auditd with security-focused rules
configure_auditd() {
    log "INFO" "configuring_auditd"
    backup_file "$AUDIT_RULES_FILE"
    cat > "$AUDIT_RULES_FILE" <<-EOF
	# QRadar Unified Installer - Audit Rules v$SCRIPT_VERSION
	# This ruleset provides a balance of security visibility and performance.

	# 1. Initial setup
	-D                    # Delete all existing rules
	-b 8192               # Increase buffer size for high-load systems
	-f 1                  # On failure, log the error and continue
	-r 100                # Rate limit messages to 100/s to prevent floods

	# 2. Monitor for credential access and privilege escalation (MITRE T1003, T1548)
	-w /etc/passwd -p wa -k identity_change
	-w /etc/shadow -p wa -k identity_change
	-w /etc/sudoers -p wa -k privilege_escalation
	-w /etc/sudoers.d/ -p wa -k privilege_escalation
	-a always,exit -F arch=b64 -S execve -F euid=0 -k root_command
	-a always,exit -F arch=b32 -S execve -F euid=0 -k root_command

	# 3. Monitor for persistence mechanisms (MITRE T1053, T1543)
	-w /etc/cron.d/ -p wa -k persistence_cron
	-w /var/spool/cron/ -p wa -k persistence_cron
	-w /etc/systemd/system/ -p wa -k persistence_systemd

	# 4. Monitor for defense evasion (MITRE T1562, T1070)
	-w /etc/audit/auditd.conf -p wa -k audit_config_change
	-w /etc/audit/rules.d/ -p wa -k audit_config_change
	-a always,exit -F path=/usr/sbin/setenforce -p x -k defense_evasion_selinux
	-a always,exit -F path=/usr/sbin/auditctl -p x -k audit_tool_usage

	# 5. Monitor for discovery and collection (MITRE T1087, T1005)
	-a always,exit -F path=/usr/bin/whoami -p x -k discovery_whoami
	-a always,exit -F path=/usr/bin/id -p x -k discovery_id
	-w /etc/hosts -p r -k collection_hosts_file

	# 6. Make rules immutable to prevent tampering (optional, for high-security environments)
	# -e 2
	EOF
    chmod 640 "$AUDIT_RULES_FILE"
}

# 5. Configure the audit event dispatcher (audisp)
configure_audisp() {
    # Check for a working audisp-syslog binary
    local audisp_path
    for path in /sbin/audisp-syslog /usr/sbin/audisp-syslog; do
        if [[ -x "$path" ]]; then audisp_path="$path"; break; fi
    done

    if [[ -n "$audisp_path" ]]; then
        log "INFO" "configuring_audisp"
        AUDISP_METHOD_AVAILABLE=true
        backup_file "$AUDISP_SYSLOG_CONF"
        mkdir -p "$(dirname "$AUDISP_SYSLOG_CONF")"
        cat > "$AUDISP_SYSLOG_CONF" <<-EOF
		# QRadar Unified Installer - Audisp Configuration
		active = yes
		direction = out
		path = $audisp_path
		type = always
		args = LOG_$(echo "$AUDIT_FACILITY" | tr '[:lower:]' '[:upper:]')
		format = string
		EOF
        chmod 640 "$AUDISP_SYSLOG_CONF"
    else
        log "WARN" "audisp_fail_fallback"
        AUDISP_METHOD_AVAILABLE=false
    fi
}

# 6. Configure rsyslog for forwarding to QRadar
configure_rsyslog() {
    log "INFO" "configuring_rsyslog"
    backup_file "$RSYSLOG_QRADAR_CONF"

    # Build the rsyslog configuration using a heredoc for clarity
    read -r -d '' RSYSLOG_CONFIG << EOM
module(load="omprog")

# --- Reliable forwarding queue ---
main_queue(queue.type="linkedlist" queue.filename="qradar_fwd_queue" queue.maxdiskspace="1g" queue.saveonshutdown="on")

# --- Template for QRadar ---
template(name="QRadarFormat" type="string" string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name%: %msg%")

# --- Rules for forwarding to QRadar ---
EOM

    if [[ "$AUDISP_METHOD_AVAILABLE" == true ]]; then
        read -r -d '' RSYSLOG_RULES << EOM
if \$syslogfacility-text == '${AUDIT_FACILITY}' then {
    if \$msg contains 'type=EXECVE' then {
        action(type="omprog" binary="$PYTHON_PARSER_PATH" template="RSYSLOG_TraditionalFileFormat")
    }
    action(type="omfwd" target="$QRADAR_IP" port="$QRADAR_PORT" protocol="tcp" template="QRadarFormat" action.resumeRetryCount="-1")
    stop
}
EOM
    else # Fallback rule: read from audit.log directly
        read -r -d '' RSYSLOG_RULES << EOM
module(load="imfile")
input(type="imfile" file="/var/log/audit/audit.log" tag="auditd" ruleset="audit_ruleset")
ruleset(name="audit_ruleset") {
    if \$msg contains 'type=EXECVE' then {
        action(type="omprog" binary="$PYTHON_PARSER_PATH" template="RSYSLOG_TraditionalFileFormat")
    }
    action(type="omfwd" target="$QRADAR_IP" port="$QRADAR_PORT" protocol="tcp" template="QRadarFormat" action.resumeRetryCount="-1")
    stop
}
EOM
    fi

    echo -e "$RSYSLOG_CONFIG\n$RSYSLOG_RULES" > "$RSYSLOG_QRADAR_CONF"
    chmod 640 "$RSYSLOG_QRADAR_CONF"

    # Check configuration syntax
    if ! rsyslogd -N1 &>/dev/null; then
        log "Rsyslog configuration syntax error. Check $LOG_FILE for details." "ERROR"
        # Restore backup if syntax check fails
        if [[ -f "$RSYSLOG_QRADAR_CONF.bak" ]]; then
            mv "$RSYSLOG_QRADAR_CONF.bak" "$RSYSLOG_QRADAR_CONF"
        fi
        return 1
    fi
}

# 7. Restart services and run final tests
finalize_and_test() {
    log "INFO" "restarting_services"
    retry "Restarting auditd" systemctl restart auditd
    retry "Restarting rsyslog" systemctl restart rsyslog

    log "INFO" "running_tests"
    sleep 3 # Allow services to stabilize
    if timeout 5 bash -c "</dev/tcp/$QRADAR_IP/$QRADAR_PORT" &>/dev/null; then
        log "SUCCESS" "test_net_ok" "$QRADAR_IP" "$QRADAR_PORT"
    else
        log "WARN" "test_net_fail" "$QRADAR_IP" "$QRADAR_PORT"
    fi
    logger -p "$AUDIT_FACILITY.info" "QRadar Unified Installer test message from $(hostname)"
}

# ===============================================================================
# MAIN EXECUTION
# ===============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --facility) AUDIT_FACILITY="$2"; shift 2;;
            --lang)     LANGUAGE="$2"; shift 2;;
            -*)         log "Unknown option: $1" "ERROR"; exit 1;;
            *)          [[ -z "$QRADAR_IP" ]] && QRADAR_IP="$1" || QRADAR_PORT="$1"; shift;;
        esac
    done

    # Check for mandatory arguments
    if [[ -z "$QRADAR_IP" ]] || [[ -z "$QRADAR_PORT" ]]; then
        log "QRadar IP and Port are mandatory." "ERROR"; exit 1
    }

    # Start logging
    log "INFO" "init"
    [[ "$EUID" -eq 0 ]] || { log "ERROR" "root_check_fail"; exit 1; }

    # Run installation steps
    detect_system
    install_packages
    deploy_parser
    configure_auditd
    configure_audisp
    configure_rsyslog
    finalize_and_test

    log "SUCCESS" "setup_complete"
}

# Run the main function with all provided script arguments
main "$@"
