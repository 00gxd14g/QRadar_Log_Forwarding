#!/bin/bash
set -e

# ------------------------------------------------------------------------------
# Combined Auditd & Rsyslog Setup Script
# Enhanced version with comprehensive error handling and logging
# ------------------------------------------------------------------------------

# Global variables
LOG_FILE="/var/log/setup_logging_combined.log"
SYSLOG_CONF="/etc/rsyslog.d/00-siem.conf"
AUDITD_CONF="/etc/audit/auditd.conf"
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
AUDISP_CONF="/etc/audit/plugins.d/syslog.conf"
AUDITD_LOG_FILE="/var/log/audit/audit.log"

# Ensure log file is writable
touch "$LOG_FILE" 2>/dev/null || { echo "ERROR: Cannot write to $LOG_FILE" >&2; exit 1; }
chmod 640 "$LOG_FILE" 2>/dev/null || { echo "ERROR: Cannot set permissions on $LOG_FILE" >&2; exit 1; }

# Logging function with timestamp and error handling
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

# Distribution detection
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

log "Detected: $DISTRO $VERSION_ID, Syslog: $SYSLOG_FILE"

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
    
    # Backup and configure auditd.conf
    [ -f "$AUDITD_CONF" ] && cp "$AUDITD_CONF" "${AUDITD_CONF}.bak" 2>/dev/null || log "WARNING: Could not backup $AUDITD_CONF"
    echo "log_facility = local3" > "$AUDITD_CONF" 2>/dev/null || error_exit "Failed to update $AUDITD_CONF"
    log "auditd.conf updated with log_facility = local3."
    
    # Ensure the directory for audit rules exists
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")" || error_exit "Failed to create directory for audit rules"
    
    # Backup and configure audit rules
    [ -f "$AUDIT_RULES_FILE" ] && cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.bak" 2>/dev/null || log "WARNING: Could not backup $AUDIT_RULES_FILE"
    
    cat > "$AUDIT_RULES_FILE" << 'EOF' || error_exit "Failed to write audit rules"
-D
-b 8192
-f 1
-i
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools
-w /var/log/audit/ -k audit_log_access
-w /etc/passwd -p wa -k passwd_modifications
-w /etc/shadow -p wa -k passwd_modifications
-w /etc/group -p wa -k group_modifications
-w /etc/gshadow -p wa -k group_modifications
-w /etc/sudoers -p wa -k sudo_modifications
-w /etc/sudoers.d -p wa -k sudo_modifications
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_command
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_command
-a always,exit -F arch=b64 -S execve -F euid>=1000 -k user_command
-a always,exit -F arch=b32 -S execve -F euid>=1000 -k user_command
-a always,exit -F arch=b64 -S execve -k user_commands
-a always,exit -F arch=b32 -S execve -k user_commands
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-w /etc/hosts -p wa -k network_modifications
-w /etc/network/ -p wa -k network_modifications
-w /sbin/shutdown -p x -k system_state_modifications
-w /sbin/poweroff -p x -k system_state_modifications
-w /sbin/reboot -p x -k system_state_modifications
-w /sbin/halt -p x -k system_state_modifications
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k kernel_modules
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k kernel_modules
-w /etc/modprobe.conf -p wa -k kernel_modules
-w /etc/pam.d/ -p wa -k pam_modifications
-w /var/log/faillog -p wa -k login_modifications
-w /var/log/lastlog -p wa -k login_modifications
-w /bin/su -p x -k su_execution
-w /usr/bin/sudo -p x -k sudo_execution
-w /tmp -p x -k suspect_activity
-w /var/tmp -p x -k suspect_activity
-w /usr/bin/wget -p x -k suspect_activity
-w /usr/bin/curl -p x -k suspect_activity
-w /bin/nc -p x -k suspect_activity
-w /usr/bin/ssh -p x -k suspect_activity
-a always,exit -F arch=b64 -S ptrace -k suspect_activity
-a always,exit -F arch=b32 -S ptrace -k suspect_activity
-e 2
EOF

    chmod 640 "$AUDIT_RULES_FILE" 2>/dev/null || error_exit "Failed to set audit rules permissions"
    
    systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart auditd"
    systemctl enable auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable auditd"
}

configure_auditd || error_exit "Auditd configuration failed"
log "auditd configured successfully"

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
    
    # Ensure the directory for audisp config exists
    mkdir -p "$(dirname "$AUDISP_CONF")" || error_exit "Failed to create directory for audisp config"
    
    cat > "$AUDISP_CONF" << EOF || error_exit "Failed to configure audisp-syslog"
active = yes
direction = out
path = $AUDISP_SYSLOG_PATH
type = always
args = LOG_LOCAL3
format = string
EOF
    
    chmod 640 "$AUDISP_CONF" 2>/dev/null || error_exit "Failed to set audisp permissions"
}

configure_audisp || error_exit "audisp configuration failed"
log "audisp-syslog configured"

# Configure rsyslog
configure_rsyslog() {
    log "Configuring rsyslog..."
    [ -f "$SYSLOG_CONF" ] && cp "$SYSLOG_CONF" "${SYSLOG_CONF}.bak" 2>/dev/null || log "WARNING: Could not backup $SYSLOG_CONF"
    
    cat > "$SYSLOG_CONF" << EOF || error_exit "Failed to write rsyslog config"
if \$syslogfacility-text == "kern" then {
    stop
}
if \$syslogfacility-text == "local3" then {
    if \$msg contains "type=EXECVE" then {
        set \$regex = regex("a\\d+=\"([^\"]*)\"", \$msg);
        set \$matches = \$regex.match;
        set \$command = "";
        for i from 1 to \$matches.count do {
            set \$arg = \$matches[i][1];
            if (\$command != "") then {
                set \$command = \$command + " ";
            }
            set \$command = \$command + \$arg;
        }
        set \$msg = "type=EXECVE command=" + \$command;
    }
    action(type="omfwd" target="$SIEM_IP" port="$SIEM_PORT" protocol="tcp")
    stop
}
EOF
    
    systemctl restart rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart rsyslog"
    systemctl enable rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable rsyslog"
}

configure_rsyslog || error_exit "rsyslog configuration failed"
log "rsyslog configured successfully"

# Diagnostic functions
diagnose_services() {
    log "Running diagnostics..."
    systemctl is-active --quiet auditd || { log "WARNING: auditd not running"; systemctl start auditd; }
    systemctl is-active --quiet rsyslog || { log "WARNING: rsyslog not running"; systemctl start rsyslog; }
    
    # Test logging
    logger "Test message from setup script" || log "WARNING: logger command failed"
    sleep 2
    grep -q "Test message" "$SYSLOG_FILE" 2>/dev/null && log "Syslog test successful" || log "WARNING: Syslog test failed"
    
    # Test audit
    touch /etc/passwd || log "WARNING: Test touch failed"
    sleep 2
    ausearch -k passwd_modifications | grep -q "passwd" 2>/dev/null && log "Audit test successful" || log "WARNING: Audit test failed"
}

diagnose_services || log "WARNING: Diagnostics encountered issues"
log "Setup completed. Check $LOG_FILE for details"
exit 0
