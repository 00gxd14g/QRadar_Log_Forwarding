#!/bin/bash
set -e

# ------------------------------------------------------------------------------
# Combined Auditd & Rsyslog Setup Script
# This script configures auditd to send its logs to syslog using local3.
# It then creates an rsyslog configuration that:
#   - Discards kernel messages.
#   - For messages with "type=EXECVE", extracts all execve arguments into a
#     single "command" field.
#   - Forwards audit logs (facility local3) to the SIEM server (IP and Port
#     provided as parameters) using TCP.
#
# It also installs required packages, sets comprehensive audit rules, and
# performs diagnostic tests.
#
# Usage: sudo bash $0 <SIEM_IP> <SIEM_PORT>
# ------------------------------------------------------------------------------

# Global variables
LOG_FILE="/var/log/setup_logging_combined.log"
SYSLOG_CONF="/etc/rsyslog.d/00-siem.conf"
AUDITD_CONF="/etc/audit/auditd.conf"
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
AUDISP_CONF="/etc/audit/plugins.d/syslog.conf"
AUDITD_LOG_FILE="/var/log/audit/audit.log"

# Logging function with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

# ------------------------------------------------------------------------------
# Check for root privileges and required parameters
# ------------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    error_exit "This script must be run as root. Use sudo."
fi

if [ $# -lt 2 ]; then
    echo "Usage: $0 <SIEM_IP> <SIEM_PORT>"
    exit 1
fi

SIEM_IP="$1"
SIEM_PORT="$2"
log "SIEM IP: $SIEM_IP, Port: $SIEM_PORT"

# ------------------------------------------------------------------------------
# Distribution detection and SYSLOG file determination
# ------------------------------------------------------------------------------
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    VERSION_ID=$VERSION_ID
else
    DISTRO=$(uname -s)
    VERSION_ID=$(uname -r)
fi

case "$DISTRO" in
    ubuntu|debian|kali)
        SYSLOG_FILE="/var/log/syslog"
        ;;
    rhel|centos|oracle)
        SYSLOG_FILE="/var/log/messages"
        ;;
    *)
        error_exit "Unsupported distribution. This script supports Debian/Ubuntu/Kali, Red Hat/CentOS, and Oracle Linux."
        ;;
esac

log "Detected Distribution: $DISTRO, Version: $VERSION_ID"
log "Using Syslog file: $SYSLOG_FILE"

# ------------------------------------------------------------------------------
# Package installation function
# ------------------------------------------------------------------------------
install_packages() {
    case "$DISTRO" in
        ubuntu|debian|kali)
            log "Updating package lists (apt-get update)..."
            apt-get update >> "$LOG_FILE" 2>&1 || error_exit "apt-get update failed."
            log "Installing auditd, audispd-plugins, and rsyslog..."
            apt-get install -y auditd audispd-plugins rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Package installation failed."
            ;;
        rhel|centos|oracle)
            log "Installing audit and rsyslog packages..."
            if command -v dnf &>/dev/null; then
                dnf install -y audit rsyslog >> "$LOG_FILE" 2>&1 || error_exit "dnf package installation failed."
            else
                yum install -y audit rsyslog >> "$LOG_FILE" 2>&1 || error_exit "yum package installation failed."
            fi
            ;;
        *)
            error_exit "Unsupported distribution."
            ;;
    esac
}

install_packages
log "Packages installed successfully."

# ------------------------------------------------------------------------------
# Configure auditd
# ------------------------------------------------------------------------------
log "Configuring auditd..."

# Backup and update auditd.conf (set log_facility to local3)
if [ -f "$AUDITD_CONF" ]; then
    cp "$AUDITD_CONF" "${AUDITD_CONF}.bak" || error_exit "Failed to backup $AUDITD_CONF"
fi
echo "log_facility = local3" > "$AUDITD_CONF" || error_exit "Failed to update $AUDITD_CONF"

# Backup existing audit rules file if present
if [ -f "$AUDIT_RULES_FILE" ]; then
    cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.bak" || error_exit "Failed to backup audit rules file"
fi

# Define comprehensive audit rules (includes execve monitoring and other checks)
read -r -d '' AUDIT_RULES_CONTENT << 'EOF'
## Clear existing rules
-D

## Set buffer size and failure mode
-b 8192
-f 1
-i

##########################################
# Self-Audit (Configuration Changes)
##########################################
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools

# Audit log access
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
# Execve (Command Execution) Monitoring
##########################################
# Monitor execve syscalls for root and non-root users
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_command
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_command
-a always,exit -F arch=b64 -S execve -F euid>=1000 -k user_command
-a always,exit -F arch=b32 -S execve -F euid>=1000 -k user_command
-a always,exit -F arch=b64 -S execve -k user_commands
-a always,exit -F arch=b32 -S execve -k user_commands

##########################################
# Network Configuration Changes
##########################################
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-w /etc/hosts -p wa -k network_modifications
-w /etc/network/ -p wa -k network_modifications

##########################################
# System State Changes
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
# Suspicious Activity
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
# Make the audit rules immutable
##########################################
-e 2
EOF

echo "$AUDIT_RULES_CONTENT" > "$AUDIT_RULES_FILE" || error_exit "Failed to write audit rules"
chmod 640 "$AUDIT_RULES_FILE" || error_exit "Failed to set permissions on audit rules file"
log "Audit rules configured successfully."

# Restart auditd
systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart auditd service."
systemctl enable auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable auditd on boot."
log "auditd configured and restarted."

# ------------------------------------------------------------------------------
# Configure audisp-syslog plugin to use local3 (instead of default local1)
# ------------------------------------------------------------------------------
log "Configuring audisp-syslog plugin..."
if [ -f "/usr/sbin/audisp-syslog" ]; then
    AUDISP_SYSLOG_PATH="/usr/sbin/audisp-syslog"
elif [ -f "/usr/lib/audisp/audisp-syslog" ]; then
    AUDISP_SYSLOG_PATH="/usr/lib/audisp/audisp-syslog"
else
    error_exit "audisp-syslog binary not found."
fi

log "Found audisp-syslog binary at: $AUDISP_SYSLOG_PATH"

cat <<EOF > "$AUDISP_CONF"
active = yes
direction = out
path = $AUDISP_SYSLOG_PATH
type = always
args = LOG_LOCAL3
format = string
EOF

chmod 640 "$AUDISP_CONF" >> "$LOG_FILE" 2>&1 || error_exit "Failed to set permissions on audisp syslog config"
log "audisp-syslog plugin configured."

# ------------------------------------------------------------------------------
# Configure rsyslog
# ------------------------------------------------------------------------------
log "Configuring rsyslog..."

# Backup existing configuration if present
if [ -f "$SYSLOG_CONF" ]; then
    cp "$SYSLOG_CONF" "${SYSLOG_CONF}.bak" || error_exit "Failed to backup existing rsyslog config"
fi

# Write rsyslog configuration. This configuration:
# 1. Discards all kernel messages.
# 2. For messages from facility local3:
#    - If the message contains "type=EXECVE", extract all arguments into one "command" field.
#    - Forward the message to the SIEM server using TCP.
cat <<EOF > "$SYSLOG_CONF"
# Discard all kernel messages
if \$syslogfacility-text == "kern" then {
    stop
}

# Process audit logs from local3
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

# Restart rsyslog service
systemctl restart rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart rsyslog service."
systemctl enable rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable rsyslog on boot."
log "rsyslog configured and restarted."

# ------------------------------------------------------------------------------
# Diagnostic Functions
# ------------------------------------------------------------------------------

diagnose_rsyslog() {
    log "----- RSYSLOG Diagnostic -----"
    if ! systemctl is-active --quiet rsyslog; then
        log "rsyslog service is not active. Attempting to start..."
        systemctl start rsyslog >> "$LOG_FILE" 2>&1 || { log "ERROR: Failed to start rsyslog."; return; }
        log "rsyslog service started."
    else
        log "rsyslog service is active."
    fi

    rsyslogd -N1 >> "$LOG_FILE" 2>&1
    if [ $? -eq 0 ]; then
        log "rsyslog configuration validated."
    else
        log "ERROR: rsyslog configuration error. Please review $SYSLOG_CONF."
    fi
    log "----- RSYSLOG Diagnostic End -----"
}

diagnose_auditd() {
    log "----- AUDITD Diagnostic -----"
    if ! systemctl is-active --quiet auditd; then
        log "auditd service is not active. Attempting to start..."
        systemctl start auditd >> "$LOG_FILE" 2>&1 || { log "ERROR: Failed to start auditd."; return; }
        log "auditd service started."
    else
        log "auditd service is active."
    fi

    if grep -iq "error" "$AUDITD_LOG_FILE"; then
        log "ERROR: Errors found in auditd log."
    else
        log "No errors found in auditd log."
    fi

    if auditctl -l | grep -q "execve"; then
        log "Audit rules (execve) are loaded."
    else
        log "ERROR: Audit rules for execve not found."
    fi
    log "----- AUDITD Diagnostic End -----"
}

diagnose_permissions() {
    log "----- Permissions Diagnostic -----"
    if [ -f "$SYSLOG_FILE" ]; then
        ls -l "$SYSLOG_FILE" >> "$LOG_FILE" 2>&1 || log "ERROR: Unable to list $SYSLOG_FILE"
    else
        log "ERROR: $SYSLOG_FILE does not exist."
    fi
    log "----- Permissions Diagnostic End -----"
}

diagnose_selinux_apparmor() {
    log "----- SELinux/AppArmor Diagnostic -----"
    if command -v getenforce &>/dev/null; then
        SELINUX_STATUS=$(getenforce)
        log "SELinux status: $SELINUX_STATUS"
        if [ "$SELINUX_STATUS" != "Disabled" ]; then
            log "SELinux is enabled; ensure proper permissions for auditd and rsyslog."
        fi
    else
        log "SELinux not available."
    fi

    if command -v aa-status &>/dev/null; then
        APPARMOR_STATUS=$(aa-status | grep "profiles are in enforce mode")
        if [ -n "$APPARMOR_STATUS" ]; then
            log "AppArmor is enabled."
        else
            log "AppArmor is disabled."
        fi
    else
        log "AppArmor not available."
    fi
    log "----- SELinux/AppArmor Diagnostic End -----"
}

# ------------------------------------------------------------------------------
# Final Checks and Diagnostics
# ------------------------------------------------------------------------------

# Verify services are running
if systemctl is-active --quiet auditd && systemctl is-active --quiet rsyslog; then
    log "Configuration completed successfully."
    log "Verify by:"
    log "1. Checking the SIEM server ($SIEM_IP:$SIEM_PORT) for received logs."
    log "2. Running commands that invoke execve and confirming logs show a single command field."
    log "3. Confirming kernel logs are discarded and not forwarded."
else
    error_exit "One or more services are not running. Please review the configuration."
fi

# Simple tests
log "Sending a test message to local syslog..."
logger "Test message from setup_logging_combined.sh script."
sleep 2
if grep -q "Test message from setup_logging_combined.sh script." "$SYSLOG_FILE"; then
    log "Test message found in syslog."
else
    log "WARNING: Test message not found in syslog. Running rsyslog diagnostics."
    diagnose_rsyslog
fi

log "Performing audit log test by touching /etc/passwd..."
touch /etc/passwd
sleep 2
if ausearch -k passwd_modifications | grep -q "name=\"/etc/passwd\""; then
    log "Audit log for /etc/passwd modification found."
else
    log "WARNING: Audit log for /etc/passwd modification not found. Running auditd diagnostics."
    diagnose_auditd
fi

diagnose_permissions
diagnose_selinux_apparmor

log "Setup script completed successfully."
exit 0
