#!/usr/bin/env bash
#
# ===============================================================================
# QRadar LEEF v2 Optimizer for Universal Installer v4.1.0
# ===============================================================================
#
# Bu script mevcut QRadar kurulumunu LEEF v2 format ve best practices'e
# göre optimize eder. IBM QRadar için minimal logging implementation guide
# önerilerine uygun olarak yapılandırır.
#
# Özellikler:
#   - LEEF v2 format implementasyonu
#   - TLS encryption desteği (port 6514)
#   - Minimal auditd rules (5 kritik kategori)
#   - EPS optimizasyonu
#   - QRadar DSM field mapping
#
# Kullanım: sudo bash qradar_leef_optimizer.sh <QRADAR_IP> <QRADAR_PORT> [--tls] [--minimal]
#
# Yazar: QRadar Log Forwarding Project
# Sürüm: 4.1.0 - LEEF v2 Optimization
# ===============================================================================

set -euo pipefail

# ===============================================================================
# GLOBAL DEĞIŞKENLER
# ===============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="4.1.0-leef-optimizer"
readonly LOG_FILE="/var/log/qradar_leef_optimizer.log"

# Configuration files
readonly AUDIT_RULES_MINIMAL="/etc/audit/rules.d/10-qradar-minimal.rules"
readonly RSYSLOG_LEEF_CONF="/etc/rsyslog.d/40-qradar-leef.conf"
readonly TLS_CERT_DIR="/etc/ssl/qradar"

# Options
USE_TLS=false
USE_MINIMAL_RULES=false
QRADAR_IP=""
QRADAR_PORT="514"

# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

log() {
    local level="${1:-INFO}"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

success() {
    log "SUCCESS" "$1"
    echo "✓ $1"
}

error_exit() {
    log "ERROR" "$1"
    echo "HATA: $1" >&2
    exit 1
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.leef-backup.$(date +%Y%m%d_%H%M%S)"
        log "INFO" "Backup created: ${file}.leef-backup.*"
    fi
}

# ===============================================================================
# MINIMAL AUDITD RULES IMPLEMENTATION
# ===============================================================================

create_minimal_audit_rules() {
    log "INFO" "Creating minimal auditd rules for QRadar optimization..."
    
    backup_file "$AUDIT_RULES_MINIMAL"
    
    cat > "$AUDIT_RULES_MINIMAL" << 'EOF'
# QRadar LEEF v2 Minimal Audit Rules - 5 Critical Categories
# Based on IBM QRadar Minimal Logging Implementation Guide
# EPS optimized for enterprise environments

## Delete all existing rules and start fresh
-D

## Buffer configuration for minimal logging
-b 4096
-f 1
-r 50

##############################################################################
# CATEGORY 1: PROCESS EXECUTION MONITORING
# Critical for threat detection and command reconstruction
##############################################################################

# User command execution (non-system users only)
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k user_commands
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k user_commands

# Root/privileged command execution
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_commands

##############################################################################
# CATEGORY 2: AUTHENTICATION & PRIVILEGE ESCALATION
# Critical for detecting unauthorized access attempts
##############################################################################

# Authentication events
-w /var/log/auth.log -p wa -k authentication
-w /var/log/secure -p wa -k authentication

# Privilege escalation tools
-w /usr/bin/sudo -p x -k privileged_commands
-w /bin/su -p x -k privileged_commands
-w /usr/bin/pkexec -p x -k privileged_commands

##############################################################################
# CATEGORY 3: CRITICAL FILE ACCESS
# Monitor access to sensitive system files only
##############################################################################

# Identity and authentication files
-w /etc/passwd -p wa -k identity_files
-w /etc/shadow -p wa -k identity_files  
-w /etc/sudoers -p wa -k identity_files
-w /etc/sudoers.d/ -p wa -k identity_files

##############################################################################
# CATEGORY 4: SERVICE STATE MONITORING
# Track critical service modifications
##############################################################################

# Service control commands
-w /usr/bin/systemctl -p x -k service_control
-w /sbin/service -p x -k service_control

##############################################################################
# CATEGORY 5: SYSTEM SHUTDOWN/REBOOT
# Track system state changes
##############################################################################

# System shutdown and reboot
-w /sbin/shutdown -p x -k system_shutdown
-w /sbin/reboot -p x -k system_reboot
-w /sbin/halt -p x -k system_shutdown

##############################################################################
# NOISE REDUCTION - EXCLUDE HIGH-VOLUME LOW-VALUE EVENTS
##############################################################################

# Exclude service start/stop messages
-a exclude,always -F msgtype=SERVICE_START
-a exclude,always -F msgtype=SERVICE_STOP
-a exclude,always -F msgtype=BPF

# Exclude noisy system processes
-a never,exit -F exe=/usr/bin/awk
-a never,exit -F exe=/usr/bin/grep  
-a never,exit -F exe=/usr/bin/sed
-a never,exit -F exe=/bin/cat
-a never,exit -F exe=/bin/ls

# Exclude temporary directories
-a never,exit -F dir=/tmp/
-a never,exit -F dir=/var/spool/
-a never,exit -F dir=/var/tmp/

# Lock configuration (commented for flexibility)
# -e 2
EOF

    chmod 640 "$AUDIT_RULES_MINIMAL"
    success "Minimal audit rules created for EPS optimization"
}

# ===============================================================================
# LEEF v2 RSYSLOG CONFIGURATION
# ===============================================================================

create_leef_rsyslog_config() {
    log "INFO" "Creating LEEF v2 rsyslog configuration..."
    
    backup_file "$RSYSLOG_LEEF_CONF"
    
    # Determine if TLS should be used
    local tls_config=""
    local target_config=""
    
    if [[ "$USE_TLS" == true ]]; then
        tls_config='
# TLS Configuration
global(
    DefaultNetstreamDriverCAFile="/etc/ssl/certs/ca-certificates.crt"
    DefaultNetstreamDriverCertFile="/etc/ssl/qradar/rsyslog-cert.pem"
    DefaultNetstreamDriverKeyFile="/etc/ssl/qradar/rsyslog-key.pem"
    DefaultNetstreamDriver="gtls"
)'
        target_config="action(
            type=\"omfwd\"
            target=\"$QRADAR_IP\"
            port=\"$QRADAR_PORT\"
            protocol=\"tcp\"
            StreamDriver=\"gtls\"
            StreamDriverMode=\"1\"
            StreamDriverAuthMode=\"x509/name\"
            StreamDriverPermittedPeer=\"$QRADAR_IP\"
            compression.mode=\"single\"
            template=\"LEEFv2Audit\"
            queue.type=\"LinkedList\"
            queue.filename=\"qradar-leef-fwd\"
            queue.maxdiskspace=\"500m\"
            action.resumeRetryCount=\"-1\"
            action.reportSuspension=\"on\"
        )"
    else
        target_config="action(
            type=\"omfwd\"
            target=\"$QRADAR_IP\"
            port=\"$QRADAR_PORT\"
            protocol=\"tcp\"
            template=\"LEEFv2Audit\"
            queue.type=\"LinkedList\"
            queue.filename=\"qradar-leef-fwd\"
            queue.maxdiskspace=\"500m\"
            action.resumeRetryCount=\"-1\"
            action.reportSuspension=\"on\"
        )"
    fi
    
    cat > "$RSYSLOG_LEEF_CONF" << EOF
# QRadar LEEF v2 Rsyslog Configuration
# Optimized for IBM QRadar SIEM integration
# Version: 4.1.0

module(load="imfile")
module(load="mmjsonparse")

$tls_config

# Rate limiting for EPS control
\$SystemLogRateLimitInterval 2
\$SystemLogRateLimitBurst 100

##############################################################################
# LEEF v2 TEMPLATES FOR QRADAR INTEGRATION
##############################################################################

# LEEF v2 template for audit events with command reconstruction
template(name="LEEFv2Audit" type="string" 
         string="LEEF:2.0|Linux|auditd|2024.1|%\$.audit_type%|^|devTime=%timereported:::date-rfc3339%^src=%hostname%^auid=%\$.auid%^uid=%\$.uid%^euid=%\$.euid%^pid=%\$.pid%^exe=%\$.exe%^cmd=%\$.full_command%^success=%\$.success%^key=%\$.key%^msg=%rawmsg%\\n")

# LEEF v2 template for authentication events  
template(name="LEEFv2Auth" type="string"
         string="LEEF:2.0|Linux|auth|2024.1|Authentication|^|devTime=%timereported:::date-rfc3339%^src=%hostname%^user=%\$.user%^result=%\$.result%^method=%\$.method%^msg=%rawmsg%\\n")

##############################################################################
# AUDIT LOG PROCESSING WITH COMMAND RECONSTRUCTION
##############################################################################

input(type="imfile"
      file="/var/log/audit/audit.log"
      tag="auditd"
      severity="info"
      facility="local6"
      ruleset="auditd_leef_processing")

ruleset(name="auditd_leef_processing") {
    if \$msg contains "type=" then {
        # Extract basic audit fields
        set \$.audit_type = regex_extract(\$msg, "type=([A-Z_]+)", 0, 1, "UNKNOWN");
        set \$.auid = regex_extract(\$msg, "auid=([0-9-]+)", 0, 1, "-1");
        set \$.uid = regex_extract(\$msg, "uid=([0-9]+)", 0, 1, "-1");
        set \$.euid = regex_extract(\$msg, "euid=([0-9]+)", 0, 1, "-1");
        set \$.pid = regex_extract(\$msg, "pid=([0-9]+)", 0, 1, "-1");
        set \$.exe = regex_extract(\$msg, "exe=\\"([^\\"]+)\\"", 0, 1, "unknown");
        set \$.success = regex_extract(\$msg, "success=([a-z]+)", 0, 1, "unknown");
        set \$.key = regex_extract(\$msg, "key=\\"([^\\"]+)\\"", 0, 1, "none");
        
        # EXECVE command reconstruction (single-field solution)
        if \$.audit_type == "EXECVE" then {
            set \$.a0 = regex_extract(\$msg, "a0=\\"([^\\"]+)\\"", 0, 1, "");
            set \$.a1 = regex_extract(\$msg, "a1=\\"([^\\"]+)\\"", 0, 1, "");
            set \$.a2 = regex_extract(\$msg, "a2=\\"([^\\"]+)\\"", 0, 1, "");
            set \$.a3 = regex_extract(\$msg, "a3=\\"([^\\"]+)\\"", 0, 1, "");
            set \$.a4 = regex_extract(\$msg, "a4=\\"([^\\"]+)\\"", 0, 1, "");
            set \$.a5 = regex_extract(\$msg, "a5=\\"([^\\"]+)\\"", 0, 1, "");
            set \$.a6 = regex_extract(\$msg, "a6=\\"([^\\"]+)\\"", 0, 1, "");
            set \$.a7 = regex_extract(\$msg, "a7=\\"([^\\"]+)\\"", 0, 1, "");
            
            # Build complete command line
            set \$.full_command = \$.a0;
            if \$.a1 != "" then set \$.full_command = \$.full_command & " " & \$.a1;
            if \$.a2 != "" then set \$.full_command = \$.full_command & " " & \$.a2;
            if \$.a3 != "" then set \$.full_command = \$.full_command & " " & \$.a3;
            if \$.a4 != "" then set \$.full_command = \$.full_command & " " & \$.a4;
            if \$.a5 != "" then set \$.full_command = \$.full_command & " " & \$.a5;
            if \$.a6 != "" then set \$.full_command = \$.full_command & " " & \$.a6;
            if \$.a7 != "" then set \$.full_command = \$.full_command & " " & \$.a7;
        } else {
            set \$.full_command = "N/A";
        }
        
        # Forward to QRadar with LEEF v2 format
        $target_config
    }
}

##############################################################################
# AUTHENTICATION LOG PROCESSING
##############################################################################

input(type="imfile"
      file="/var/log/auth.log"
      tag="auth"
      severity="info"
      facility="authpriv"
      ruleset="auth_leef_processing")

# Fallback for RHEL systems
input(type="imfile"
      file="/var/log/secure"
      tag="auth-rhel"
      severity="info"
      facility="authpriv"
      ruleset="auth_leef_processing")

ruleset(name="auth_leef_processing") {
    # Extract authentication fields
    set \$.user = regex_extract(\$msg, "user=([a-zA-Z0-9_-]+)", 0, 1, "unknown");
    set \$.result = "unknown";
    set \$.method = "unknown";
    
    # Determine authentication result
    if \$msg contains "FAILED" or \$msg contains "failed" then set \$.result = "failure";
    if \$msg contains "SUCCESS" or \$msg contains "Accepted" then set \$.result = "success";
    
    # Determine authentication method
    if \$msg contains "sudo" then set \$.method = "sudo";
    if \$msg contains "ssh" then set \$.method = "ssh";
    if \$msg contains "su:" then set \$.method = "su";
    
    # Forward critical auth events only
    if \$.result != "unknown" then {
        $target_config
    }
}

##############################################################################
# NOISE REDUCTION AND EPS OPTIMIZATION
##############################################################################

# Drop noisy system messages
if \$msg contains "systemd:" or \$msg contains "NetworkManager" or \$msg contains "dhclient" then stop;

# Drop kernel messages unless critical
if \$syslogfacility-text == "kern" and not (\$msg contains "denied" or \$msg contains "blocked") then stop;

# Drop routine maintenance messages
if \$msg contains "logrotate" or \$msg contains "anacron" then stop;

EOF

    chmod 644 "$RSYSLOG_LEEF_CONF"
    success "LEEF v2 rsyslog configuration created"
}

# ===============================================================================
# TLS CERTIFICATE MANAGEMENT
# ===============================================================================

setup_tls_certificates() {
    if [[ "$USE_TLS" != true ]]; then
        return 0
    fi
    
    log "INFO" "Setting up TLS certificates for secure QRadar communication..."
    
    mkdir -p "$TLS_CERT_DIR"
    
    # Check if certificates already exist
    if [[ -f "$TLS_CERT_DIR/rsyslog-cert.pem" ]]; then
        log "INFO" "TLS certificates already exist, skipping generation"
        return 0
    fi
    
    # Generate self-signed certificate for testing
    log "INFO" "Generating self-signed certificate for TLS testing..."
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$TLS_CERT_DIR/rsyslog-key.pem" \
        -out "$TLS_CERT_DIR/rsyslog-cert.pem" \
        -subj "/C=TR/ST=Istanbul/L=Istanbul/O=QRadar/OU=LogForwarding/CN=$QRADAR_IP" \
        2>/dev/null || {
            warn "Failed to generate certificates, TLS will be disabled"
            USE_TLS=false
            return 1
        }
    
    chmod 600 "$TLS_CERT_DIR/rsyslog-key.pem"
    chmod 644 "$TLS_CERT_DIR/rsyslog-cert.pem"
    
    success "TLS certificates generated for secure communication"
}

# ===============================================================================
# SERVICE MANAGEMENT AND OPTIMIZATION
# ===============================================================================

optimize_services() {
    log "INFO" "Optimizing services for LEEF v2 configuration..."
    
    # Load minimal audit rules if specified
    if [[ "$USE_MINIMAL_RULES" == true ]]; then
        log "INFO" "Loading minimal audit rules for EPS optimization..."
        
        # Stop auditd
        systemctl stop auditd || true
        sleep 2
        
        # Load minimal rules
        if auditctl -R "$AUDIT_RULES_MINIMAL" 2>/dev/null; then
            success "Minimal audit rules loaded successfully"
        else
            warn "Failed to load minimal rules, falling back to line-by-line loading"
            auditctl -D
            while IFS= read -r line; do
                if [[ -n "$line" ]] && [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ "$line" =~ ^[[:space:]]*- ]]; then
                    auditctl "$line" 2>/dev/null || true
                fi
            done < "$AUDIT_RULES_MINIMAL"
        fi
        
        # Start auditd
        systemctl start auditd || error_exit "Failed to start auditd"
    fi
    
    # Restart rsyslog with LEEF configuration
    log "INFO" "Restarting rsyslog with LEEF v2 configuration..."
    
    # Validate rsyslog configuration
    if rsyslogd -N1 2>/dev/null; then
        success "Rsyslog configuration validated"
    else
        error_exit "Rsyslog configuration validation failed"
    fi
    
    systemctl restart rsyslog || error_exit "Failed to restart rsyslog"
    
    success "Services optimized for LEEF v2"
}

# ===============================================================================
# TESTING AND VALIDATION
# ===============================================================================

run_leef_tests() {
    log "INFO" "Running LEEF v2 configuration tests..."
    
    # Test 1: Service status
    for service in auditd rsyslog; do
        if systemctl is-active --quiet "$service"; then
            success "$service service is running"
        else
            error_exit "$service service is not running"
        fi
    done
    
    # Test 2: Generate test audit event
    log "INFO" "Generating test audit events..."
    sudo touch /etc/passwd >/dev/null 2>&1 || true
    sleep 2
    
    # Test 3: Check if events are being processed
    if tail -20 /var/log/audit/audit.log | grep -q "identity_files"; then
        success "Audit events are being generated"
    else
        warn "No audit events found, check audit configuration"
    fi
    
    # Test 4: QRadar connectivity test
    log "INFO" "Testing QRadar connectivity..."
    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$QRADAR_IP/$QRADAR_PORT" 2>/dev/null; then
        success "QRadar connectivity test passed"
    else
        warn "Cannot connect to QRadar at $QRADAR_IP:$QRADAR_PORT"
    fi
    
    # Test 5: Generate LEEF test message
    logger -t "LEEFTest" "LEEF:2.0|Linux|Test|1.0|ConfigTest|^|src=$(hostname)^msg=LEEF v2 configuration test"
    
    success "LEEF v2 tests completed"
}

# ===============================================================================
# EPS MONITORING AND REPORTING
# ===============================================================================

generate_eps_report() {
    log "INFO" "Generating EPS (Events Per Second) analysis report..."
    
    echo ""
    echo "============================================================="
    echo "             QRadar LEEF v2 Optimization Report"
    echo "============================================================="
    echo ""
    echo "📊 CONFIGURATION SUMMARY:"
    echo "   • QRadar Target: $QRADAR_IP:$QRADAR_PORT"
    echo "   • TLS Enabled: $USE_TLS"
    echo "   • Minimal Rules: $USE_MINIMAL_RULES"
    echo "   • LEEF Format: v2.0"
    echo ""
    echo "🎯 OPTIMIZATION FEATURES:"
    echo "   • Single-field command reconstruction"
    echo "   • EPS optimized audit rules (5 categories)"
    echo "   • Advanced noise reduction"
    echo "   • QRadar DSM field mapping"
    if [[ "$USE_TLS" == true ]]; then
        echo "   • TLS encrypted transmission"
    fi
    echo ""
    echo "📈 EXPECTED EPS REDUCTION:"
    echo "   • Estimated 70-80% EPS reduction vs default configuration"
    echo "   • Focused on 5 critical security categories"
    echo "   • Optimized for QRadar parsing efficiency"
    echo ""
    echo "🔍 MONITORING COMMANDS:"
    echo "   • EPS Check: ausearch --start today | wc -l"
    echo "   • Real-time: tail -f /var/log/audit/audit.log"
    echo "   • Network: tcpdump -i any host $QRADAR_IP and port $QRADAR_PORT"
    echo "   • LEEF Test: logger -t test 'LEEF:2.0|Test|System|1.0|Test|^|msg=test'"
    echo ""
    echo "============================================================="
    echo ""
    
    success "EPS analysis report generated"
}

# ===============================================================================
# MAIN FUNCTION
# ===============================================================================

main() {
    # Initialize logging
    touch "$LOG_FILE" || error_exit "Cannot create log file: $LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null || true
    
    log "INFO" "============================================================="
    log "INFO" "QRadar LEEF v2 Optimizer v$SCRIPT_VERSION"
    log "INFO" "Starting optimization: $(date)"
    log "INFO" "============================================================="
    
    # Root check
    [[ $EUID -eq 0 ]] || error_exit "This script must be run as root. Use 'sudo'."
    
    # Check if QRadar configuration exists
    if [[ ! -f /etc/rsyslog.d/99-qradar.conf ]] && [[ ! -f /etc/audit/rules.d/99-qradar.rules ]]; then
        error_exit "No existing QRadar configuration found. Please run the main installer first."
    fi
    
    # Main optimization steps
    if [[ "$USE_MINIMAL_RULES" == true ]]; then
        create_minimal_audit_rules
    fi
    
    if [[ "$USE_TLS" == true ]]; then
        setup_tls_certificates
    fi
    
    create_leef_rsyslog_config
    optimize_services
    run_leef_tests
    generate_eps_report
    
    log "INFO" "============================================================="
    log "INFO" "LEEF v2 optimization completed: $(date)"
    log "INFO" "============================================================="
}

# ===============================================================================
# ARGUMENT PARSING AND SCRIPT ENTRY POINT
# ===============================================================================

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --tls)
            USE_TLS=true
            shift
            ;;
        --minimal)
            USE_MINIMAL_RULES=true
            shift
            ;;
        -h|--help)
            echo "QRadar LEEF v2 Optimizer v$SCRIPT_VERSION"
            echo ""
            echo "Usage: $0 <QRADAR_IP> <QRADAR_PORT> [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --tls      Enable TLS encryption (port 6514 recommended)"
            echo "  --minimal  Use minimal audit rules for EPS optimization"
            echo "  --help     Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 192.168.1.100 514"
            echo "  $0 192.168.1.100 6514 --tls"
            echo "  $0 192.168.1.100 514 --minimal"
            echo "  $0 192.168.1.100 6514 --tls --minimal"
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

# Validate required arguments
if [[ -z "$QRADAR_IP" ]] || [[ -z "$QRADAR_PORT" ]]; then
    echo "Usage: $0 <QRADAR_IP> <QRADAR_PORT> [--tls] [--minimal]"
    echo "Example: $0 192.168.1.100 6514 --tls --minimal"
    exit 1
fi

# IP address format validation
if ! [[ "$QRADAR_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    error_exit "Invalid IP address format: $QRADAR_IP"
fi

# Port number validation
if ! [[ "$QRADAR_PORT" =~ ^[0-9]+$ ]] || [[ "$QRADAR_PORT" -lt 1 ]] || [[ "$QRADAR_PORT" -gt 65535 ]]; then
    error_exit "Invalid port number: $QRADAR_PORT (must be 1-65535)"
fi

# Run main function
main

exit 0