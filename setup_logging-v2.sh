#!/bin/bash
set -e

# ------------------------------------------------------------------------------
# Auditd and Rsyslog Configuration Script
# (Based on die.net man pages: auditd.conf(8), audispd(8), auditd(8))
#
# This script:
#   - Backs up the /etc/audit/auditd.conf file (without modification),
#   - Writes the audit rules (as provided below) to /etc/audit/rules.d/audit.rules,
#   - Configures the audisp-syslog plugin in /etc/audisp/plugins.d/syslog.conf,
#   - Sets up /etc/rsyslog.d/00-siem.conf so that the omprog module sends EXECVE
#     messages to an external Python script that concatenates command arguments
#     into a single a0 field,
#   - Forwards the transformed logs via TCP to the SIEM server.
#
# Usage: sudo bash setup_logging.sh <SIEM_IP> <SIEM_PORT>
# ------------------------------------------------------------------------------

# Global variables
LOG_FILE="/var/log/setup_logging.log"
SYSLOG_CONF="/etc/rsyslog.d/00-siem.conf"
AUDITD_CONF="/etc/audit/auditd.conf"
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
AUDISP_CONF="/etc/audisp/plugins.d/syslog.conf"
AUDITD_LOG_FILE="/var/log/audit/audit.log"

# Ensure the log file is writable
touch "$LOG_FILE" 2>/dev/null || { echo "ERROR: Cannot write to $LOG_FILE" >&2; exit 1; }
chmod 640 "$LOG_FILE" 2>/dev/null || { echo "ERROR: Unable to set permissions on $LOG_FILE" >&2; exit 1; }

# Timestamped logging function
log() {
    local message
    message="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$message" | tee -a "$LOG_FILE" >/dev/null 2>&1 || {
        echo "ERROR: Failed to write to log file: $message" >&2
        return 1
    }
    echo "$message"
}

error_exit() {
    log "ERROR: $1"
    echo "ERROR: $1" >&2
    exit 1
}

# Check for root privileges and parameters
[ "$EUID" -ne 0 ] && error_exit "This script must be run as root. Use sudo."
[ $# -lt 2 ] && { echo "Usage: $0 <SIEM_IP> <SIEM_PORT>" >&2; exit 1; }

SIEM_IP="$1"
SIEM_PORT="$2"
log "Starting configuration - SIEM IP: $SIEM_IP, Port: $SIEM_PORT"

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    VERSION_ID=$VERSION_ID
else
    DISTRO=$(uname -s)
    VERSION_ID=$(uname -r)
fi

case "$DISTRO" in
    ubuntu|debian|kali) SYSLOG_FILE="/var/log/syslog";;
    rhel|centos|oracle) SYSLOG_FILE="/var/log/messages";;
    *) error_exit "Unsupported distribution: $DISTRO";;
esac

log "Detected: $DISTRO $VERSION_ID, Syslog file: $SYSLOG_FILE"

# Package installation
install_packages() {
    log "Installing required packages..."
    case "$DISTRO" in
        ubuntu|debian|kali)
            apt-get update >> "$LOG_FILE" 2>&1 || error_exit "apt-get update failed"
            apt-get install -y auditd audispd-plugins rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Package installation failed"
            ;;
        rhel|centos|oracle)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y audit rsyslog >> "$LOG_FILE" 2>&1 || error_exit "dnf installation failed"
            else
                yum install -y audit rsyslog >> "$LOG_FILE" 2>&1 || error_exit "yum installation failed"
            fi
            ;;
    esac
}

install_packages || error_exit "Package installation failed"
log "Packages installed successfully"

# Configure auditd
configure_auditd() {
    log "Configuring auditd..."
    
    # Back up auditd.conf (do not modify unsupported parameters)
    if [ -f "$AUDITD_CONF" ]; then
        cp "$AUDITD_CONF" "${AUDITD_CONF}.bak" 2>/dev/null || log "WARNING: Could not back up $AUDITD_CONF"
    fi
    log "Skipping modifications to auditd.conf as 'log_facility' is not supported."
    
    # Ensure the audit rules directory exists
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")" || error_exit "Failed to create audit rules directory"
    if [ -f "$AUDIT_RULES_FILE" ]; then
        cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.bak" 2>/dev/null || log "WARNING: Could not back up $AUDIT_RULES_FILE"
    fi
    
    # Write the audit rules (exactly as provided)
    cat > "$AUDIT_RULES_FILE" << 'EOF' || error_exit "Failed to write audit rules"
## Delete all current rules
-D

## Buffer Size
-b 8192

## Failure Mode
-f 1

## Ignore Errors
-i

##########################################
# [Self-Auditing]
##########################################
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools

# Access to audit logs
-w /var/log/audit/ -k audit_log_access

##########################################
# File System Monitoring (Examples)
##########################################
-w /etc/passwd -p wa -k passwd_modifications
-w /etc/shadow -p wa -k passwd_modifications
-w /etc/group -p wa -k group_modifications
-w /etc/gshadow -p wa -k group_modifications
-w /etc/sudoers -p wa -k sudo_modifications
-w /etc/sudoers.d -p wa -k sudo_modifications

##########################################
# Command Execution Monitoring
##########################################
-a always,exit -F arch=b64 -F euid=0 -S execve -k root_command
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_command
-a always,exit -F arch=b64 -F euid>=1000 -S execve -k user_command
-a always,exit -F arch=b32 -S execve -F euid>=1000 -k user_command

##########################################
# Network Configuration Changes
##########################################
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-w /etc/hosts -p wa -k network_modifications
-w /etc/network/ -p wa -k network_modifications

##########################################
# System Startup and Shutdown
##########################################
-w /sbin/shutdown -p x -k system_state_modifications
-w /sbin/poweroff -p x -k system_state_modifications
-w /sbin/reboot -p x -k system_state_modifications
-w /sbin/halt -p x -k system_state_modifications

##########################################
# Kernel Module Loading
##########################################
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k kernel_modules
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k kernel_modules
-w /etc/modprobe.conf -p wa -k kernel_modules

##########################################
# Authentication Events (e.g., PAM)
##########################################
-w /etc/pam.d/ -p wa -k pam_modifications
-w /var/log/faillog -p wa -k login_modifications
-w /var/log/lastlog -p wa -k login_modifications

##########################################
# Privilege Escalation
##########################################
-w /bin/su -p x -k su_execution
-w /usr/bin/sudo -p x -k sudo_execution

##########################################
# Suspicious Activities
##########################################
-w /tmp -p x -k suspect_activity
-w /var/tmp -p x -k suspect_activity
-w /usr/bin/wget -p x -k suspect_activity
-w /usr/bin/curl -p x -k suspect_activity
-w /bin/nc -p x -k suspect_activity
-w /usr/bin/ssh -p x -k suspect_activity
-a always,exit -F arch=b64 -S ptrace -k suspect_activity
-a always,exit -F arch=b32 -S ptrace -k suspect_activity

##########################################
# Monitoring All User Commands
##########################################
-a always,exit -F arch=b64 -S execve -k user_commands
-a always,exit -F arch=b32 -S execve -k user_commands
EOF
 
    chmod 640 "$AUDIT_RULES_FILE" 2>/dev/null || error_exit "Failed to set permissions on audit rules file"
    
    systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart auditd"
    systemctl enable auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable auditd"
}
 
configure_auditd || error_exit "Auditd configuration failed"
log "Auditd configured successfully"
 
# Configure audisp-syslog
configure_audisp() {
    log "Configuring audisp-syslog..."
    if [ -f "/usr/sbin/audisp-syslog" ]; then
        AUDISP_SYSLOG_PATH="/usr/sbin/audisp-syslog"
    elif [ -f "/usr/lib/audisp/audisp-syslog" ]; then
        AUDISP_SYSLOG_PATH="/usr/lib/audisp/audisp-syslog"
    else
        error_exit "audisp-syslog not found"
    fi
    
    mkdir -p "$(dirname "$AUDISP_CONF")" || error_exit "Failed to create audisp config directory"
    
    cat > "$AUDISP_CONF" << EOF || error_exit "Failed to write audisp-syslog configuration"
active = yes
direction = out
path = $AUDISP_SYSLOG_PATH
type = always
args = LOG_LOCAL3
format = string
EOF
    
    chmod 640 "$AUDISP_CONF" 2>/dev/null || error_exit "Failed to set permissions on audisp config"
}
 
configure_audisp || error_exit "Audisp configuration failed"
log "Audisp-syslog configured successfully"
 
# Configure rsyslog
configure_rsyslog() {
    log "Configuring rsyslog..."
    [ -f "$SYSLOG_CONF" ] && cp "$SYSLOG_CONF" "${SYSLOG_CONF}.bak" 2>/dev/null || log "WARNING: Could not back up $SYSLOG_CONF"
    
    cat > "$SYSLOG_CONF" << 'EOF' || error_exit "Failed to write rsyslog configuration"
module(load="omprog")

# Block kernel messages
if $syslogfacility-text == "kern" then {
    stop
}
# Process EXECVE messages coming from the local3 facility
if $syslogfacility-text == "local3" and $msg contains "type=EXECVE" then {
    # Send the message to the external Python script using omprog
    action(
         type="omprog"
         binary="/usr/local/bin/concat_execve.py"
         useTransactions="on"
         name="execve_transformer"
    )
    # Forward the transformed message to the SIEM server via TCP
    action(
         type="omfwd"
         target="$SIEM_IP"
         port="$SIEM_PORT"
         protocol="tcp"
    )
    stop
}
EOF
    
    systemctl restart rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart rsyslog"
    systemctl enable rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable rsyslog"
}
 
configure_rsyslog || error_exit "Rsyslog configuration failed"
log "Rsyslog configured successfully"
 
# Diagnostic functions
diagnose_services() {
    log "Running diagnostics..."
    systemctl is-active --quiet auditd || { log "WARNING: auditd is not running"; systemctl start auditd; }
    systemctl is-active --quiet rsyslog || { log "WARNING: rsyslog is not running"; systemctl start rsyslog; }
    
    # Syslog test: send a test message using the local3 facility
    logger -p local3.info "Test message from setup script" || log "WARNING: logger command failed"
    sleep 2
    if grep -q "Test message from setup script" "$SYSLOG_FILE"; then
        log "Syslog test successful"
    else
        log "WARNING: Syslog test failed"
    fi
    
    # Audit test: trigger a change by touching /etc/passwd
    touch /etc/passwd || log "WARNING: Test touch failed"
    sleep 2
    if ausearch -k passwd_modifications | grep -q "passwd"; then
        log "Audit test successful"
    else
        log "WARNING: Audit test failed"
    fi
}
 
diagnose_services || log "WARNING: Issues encountered during diagnostics"
log "Setup completed. Check $LOG_FILE for details"
exit 0
