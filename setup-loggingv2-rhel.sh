#!/bin/bash
set -e

# ------------------------------------------------------------------------------
# Auditd and Rsyslog Configuration Script (v2 Enhanced for RHEL)
#
# This script:
#   - Backs up relevant configuration files.
#   - Writes audit rules to /etc/audit/rules.d/audit.rules.
#   - Configures the audisp-syslog plugin to send audit logs to rsyslog's local3 facility.
#   - Deploys a Python script to /usr/local/bin/concat_execve.py.
#   - Configures rsyslog (/etc/rsyslog.d/00-siem.conf) to:
#     - Block kernel messages.
#     - Process all messages from local3 (audit logs).
#     - For local3 messages of type EXECVE, use omprog with the Python script
#       to concatenate command arguments into a single a0 field.
#     - Forward all (potentially transformed) local3 messages via TCP to the SIEM server.
#   - Adds considerations for SELinux and Firewalld on RHEL systems.
#
# Usage: sudo bash setup_logging-v2.sh <SIEM_IP> <SIEM_PORT>
# ------------------------------------------------------------------------------

# Global variables
LOG_FILE="/var/log/setup_logging.log"
SYSLOG_CONF_OUTPUT_FILE="/etc/rsyslog.d/00-siem.conf"
AUDITD_CONF_FILE="/etc/audit/auditd.conf"
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
AUDISP_PLUGIN_CONF_FILE="/etc/audisp/plugins.d/syslog.conf"
AUDITD_SYSTEM_LOG_FILE="/var/log/audit/audit.log"
CONCAT_EXECVE_SCRIPT_PATH="/usr/local/bin/concat_execve.py"

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
    echo "$message" # Also print to stdout
}

error_exit() {
    log "ERROR: $1"
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
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO=$ID
    VERSION_ID_NUM=$VERSION_ID
else
    DISTRO=$(uname -s)
    VERSION_ID_NUM=$(uname -r)
fi

LOCAL_SYSLOG_FILE=""
case "$DISTRO" in
    ubuntu|debian|kali) LOCAL_SYSLOG_FILE="/var/log/syslog";;
    rhel|centos|oracle|almalinux|rocky) LOCAL_SYSLOG_FILE="/var/log/messages";;
    *) error_exit "Unsupported distribution: $DISTRO";;
esac

log "Detected: $DISTRO $VERSION_ID_NUM, Main local syslog file: $LOCAL_SYSLOG_FILE"

# Package installation
install_packages() {
    log "Installing required packages..."
    case "$DISTRO" in
        ubuntu|debian|kali)
            apt-get update -y >> "$LOG_FILE" 2>&1 || error_exit "apt-get update failed"
            apt-get install -y auditd audispd-plugins rsyslog python3 >> "$LOG_FILE" 2>&1 || error_exit "Package installation failed (apt-get)"
            ;;
        rhel|centos|oracle|almalinux|rocky)
            if command -v dnf >/dev/null 2>&1; then # RHEL 8, 9 and derivatives
                log "Attempting to install packages with DNF..."
                dnf install -y audit rsyslog python3 rsyslog-omprog >> "$LOG_FILE" 2>&1 || error_exit "Package installation failed (dnf). Ensure rsyslog-omprog is available if omprog module fails to load."
            else # RHEL 7 and derivatives
                log "Attempting to install packages with YUM (RHEL 7)..."
                if ! yum list installed epel-release >/dev/null 2>&1; then
                    log "EPEL repository is not installed. Attempting to install EPEL release for Python 3 availability..."
                    yum install -y epel-release >> "$LOG_FILE" 2>&1 || log "WARNING: Failed to install EPEL release. Python 3 and other packages might not be available."
                    yum makecache fast >> "$LOG_FILE" 2>&1 # Update metadata after adding EPEL
                fi
                # rsyslog-omprog is typically part of the main rsyslog package on RHEL7, but explicitly list if needed
                yum install -y audit rsyslog python3 >> "$LOG_FILE" 2>&1 || {
                    log "ERROR: Package installation failed with YUM. Python 3 might require EPEL repository (epel-release) on RHEL 7."
                    error_exit "Package installation failed (yum)"
                }
            fi
            ;;
    esac
}

install_packages
log "Packages installed successfully"

# Deploy concat_execve.py script
deploy_python_script() {
    log "Deploying Python script to $CONCAT_EXECVE_SCRIPT_PATH..."
    PYTHON_SCRIPT_CONTENT='#!/usr/bin/env python3
import sys
import re

def process_line(line):
    if "type=EXECVE" not in line:
        return line
    args = re.findall(r"a\d+=\"([^\"]*)\"", line)
    if args:
        combined_command = " ".join(args)
        escaped_combined_command = combined_command.replace("\"", "\\\"")
        new_line = re.sub(r"a\d+=\"[^\"]*\"\s*", "", line).strip()
        if new_line and not new_line.endswith(" "):
            new_line += " "
        new_line += "a0=\"" + escaped_combined_command + "\""
        return "MODIFIED: " + new_line
    return line

def main():
    try:
        for line in sys.stdin:
            processed_line = process_line(line.strip())
            print(processed_line)
            sys.stdout.flush()
    except Exception as e:
        print(f"concat_execve.py ERROR: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
'
    echo "$PYTHON_SCRIPT_CONTENT" > "$CONCAT_EXECVE_SCRIPT_PATH" || error_exit "Failed to write Python script $CONCAT_EXECVE_SCRIPT_PATH"
    chmod +x "$CONCAT_EXECVE_SCRIPT_PATH" || error_exit "Failed to make Python script $CONCAT_EXECVE_SCRIPT_PATH executable"
    log "$CONCAT_EXECVE_SCRIPT_PATH deployed and made executable."
}

deploy_python_script

# Configure auditd
configure_auditd() {
    log "Configuring auditd..."
    if [ -f "$AUDITD_CONF_FILE" ]; then
        cp -p "$AUDITD_CONF_FILE" "${AUDITD_CONF_FILE}.bak.$(date +%F_%T)" 2>/dev/null || log "WARNING: Could not back up $AUDITD_CONF_FILE"
    fi
    log "Skipping direct modifications to $AUDITD_CONF_FILE."
    
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")" || error_exit "Failed to create audit rules directory $(dirname "$AUDIT_RULES_FILE")"
    if [ -f "$AUDIT_RULES_FILE" ];then
        cp -p "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.bak.$(date +%F_%T)" 2>/dev/null || log "WARNING: Could not back up $AUDIT_RULES_FILE"
    fi
    
    cat > "$AUDIT_RULES_FILE" << 'EOF' || error_exit "Failed to write audit rules to $AUDIT_RULES_FILE"
## Delete all current rules
-D
-b 8192
-f 1
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools
-w /var/log/audit/ -k audit_log_access
-w /etc/passwd -p wa -k file_passwd_changes
-w /etc/shadow -p wa -k file_shadow_changes
-w /etc/group -p wa -k file_group_changes
-w /etc/gshadow -p wa -k file_gshadow_changes
-w /etc/sudoers -p wa -k file_sudoers_changes
-w /etc/sudoers.d/ -p wa -k file_sudoers_d_changes
-a always,exit -F arch=b64 -S execve -F euid=0 -k exec_root_cmd
-a always,exit -F arch=b32 -S execve -F euid=0 -k exec_root_cmd
-a always,exit -F arch=b64 -S execve -F euid>=1000 -F auid!=4294967295 -k exec_user_cmd
-a always,exit -F arch=b32 -S execve -F euid>=1000 -F auid!=4294967295 -k exec_user_cmd
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k net_config_changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k net_config_changes
-w /etc/hosts -p wa -k net_hosts_file_changes
-w /etc/sysconfig/network-scripts/ -p wa -k rhel_net_scripts_changes # RHEL/CentOS specific
-w /etc/network/interfaces -p wa -k deb_net_interfaces_file_changes # Debian/Ubuntu
-w /etc/netplan/ -p wa -k ubuntu_netplan_changes # Ubuntu with netplan
-w /sbin/shutdown -p x -k sys_shutdown
-w /sbin/poweroff -p x -k sys_poweroff
-w /sbin/reboot -p x -k sys_reboot
-w /sbin/halt -p x -k sys_halt
-a always,exit -F path=/sbin/insmod -F perm=x -F auid!=4294967295 -k mod_insmod
-a always,exit -F path=/sbin/rmmod -F perm=x -F auid!=4294967295 -k mod_rmmod
-a always,exit -F path=/sbin/modprobe -F perm=x -F auid!=4294967295 -k mod_modprobe
-w /etc/modprobe.conf -p wa -k mod_conf_changes
-w /etc/modprobe.d/ -p wa -k mod_conf_d_changes
-w /etc/pam.d/ -p wa -k auth_pam_changes
-w /var/log/faillog -p wa -k auth_faillog_access
-w /var/log/lastlog -p wa -k auth_lastlog_access
-w /etc/login.defs -p wa -k auth_login_defs_changes
-w /etc/security/opasswd -p wa -k auth_opasswd_changes
-w /bin/su -p x -k priv_su_exec
-w /usr/bin/sudo -p x -k priv_sudo_exec
-a always,exit -F arch=b64 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k priv_escalation_syscalls
-a always,exit -F arch=b32 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k priv_escalation_syscalls
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F a1&0111 -F auid>=1000 -F auid!=4294967295 -k priv_perm_change_exec
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F a1&0111 -F auid>=1000 -F auid!=4294967295 -k priv_perm_change_exec
-w /usr/bin/wget -p x -k susp_wget
-w /usr/bin/curl -p x -k susp_curl
-w /bin/nc -p x -k susp_netcat 
-w /usr/bin/ncat -p x -k susp_ncat
## -e 2 # Make rules immutable (optional)
EOF
 
    chmod 640 "$AUDIT_RULES_FILE" || error_exit "Failed to set permissions on $AUDIT_RULES_FILE"
    
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >> "$LOG_FILE" 2>&1 || error_exit "augenrules --load failed"
    else
        auditctl -R "$AUDIT_RULES_FILE" >> "$LOG_FILE" 2>&1 || error_exit "auditctl -R $AUDIT_RULES_FILE failed"
    fi
    log "Audit rules loaded."

    systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart auditd"
    systemctl enable auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable auditd"
}
 
configure_auditd
log "Auditd configured successfully"
 
# Configure audisp-syslog plugin
configure_audisp() {
    log "Configuring audisp-syslog plugin..."
    local audisp_syslog_binary_path=""
    # Order matters: /sbin is common on RHEL for this
    if [ -f "/sbin/audisp-syslog" ]; then
        audisp_syslog_binary_path="/sbin/audisp-syslog"
    elif [ -f "/usr/sbin/audisp-syslog" ]; then 
        audisp_syslog_binary_path="/usr/sbin/audisp-syslog"
    else
        log "WARNING: audisp-syslog binary not found in /sbin/audisp-syslog or /usr/sbin/audisp-syslog. Ensure auditd can send logs to syslog via plugin."
    fi
    
    mkdir -p "$(dirname "$AUDISP_PLUGIN_CONF_FILE")" || error_exit "Failed to create audisp config directory $(dirname "$AUDISP_PLUGIN_CONF_FILE")"
    
    cat > "$AUDISP_PLUGIN_CONF_FILE" << EOF || error_exit "Failed to write audisp-syslog configuration to $AUDISP_PLUGIN_CONF_FILE"
active = yes
direction = out
path = $audisp_syslog_binary_path 
type = always
args = LOG_LOCAL3
format = string
EOF
    
    chmod 640 "$AUDISP_PLUGIN_CONF_FILE" || error_exit "Failed to set permissions on $AUDISP_PLUGIN_CONF_FILE"
    log "Audisp-syslog plugin configured to use LOG_LOCAL3."
    systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart auditd after audisp configuration"
}
 
configure_audisp
log "Audisp-syslog configured successfully"
 
# Configure rsyslog
configure_rsyslog() {
    log "Configuring rsyslog..."
    if [ -f "$SYSLOG_CONF_OUTPUT_FILE" ]; then
      cp -p "$SYSLOG_CONF_OUTPUT_FILE" "${SYSLOG_CONF_OUTPUT_FILE}.bak.$(date +%F_%T)" 2>/dev/null || log "WARNING: Could not back up $SYSLOG_CONF_OUTPUT_FILE"
    fi
    
    cat > "$SYSLOG_CONF_OUTPUT_FILE" << EOF || error_exit "Failed to write rsyslog configuration to $SYSLOG_CONF_OUTPUT_FILE"
module(load="omprog")

if \$syslogfacility-text == "kern" then {
    stop
}

if \$syslogfacility-text == "local3" then {
    if \$msg contains "type=EXECVE" then {
        action(
            type="omprog"
            binary="$CONCAT_EXECVE_SCRIPT_PATH"
            useTransactions="on"
            template="" 
            output="/var/log/omprog_execve_output.log" 
            confirmMessages="off"
            reportFailures="on"
            name="EXECVE_Argument_Concatenator"
        )
    }
    action(
        type="omfwd"
        target="$SIEM_IP"
        port="$SIEM_PORT"
        protocol="tcp"
        name="ForwardAuditToSIEM"
    )
    stop 
}
EOF
    
    log "Rsyslog configuration written to $SYSLOG_CONF_OUTPUT_FILE"
    rsyslogd -N1 -f "$SYSLOG_CONF_OUTPUT_FILE" >> "$LOG_FILE" 2>&1 || log "WARNING: Rsyslog configuration validation reported issues for $SYSLOG_CONF_OUTPUT_FILE."

    systemctl restart rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart rsyslog"
    systemctl enable rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable rsyslog"
}
 
configure_rsyslog
log "Rsyslog configured successfully"

# Configure SELinux and Firewall for RHEL/CentOS/Oracle/Alma/Rocky
configure_rhel_specifics() {
    if [[ "$DISTRO" == "rhel" || "$DISTRO" == "centos" || "$DISTRO" == "oracle" || "$DISTRO" == "almalinux" || "$DISTRO" == "rocky" ]]; then
        log "Performing RHEL-specific configurations (SELinux, Firewall)..."
        # SELinux configuration
        if command -v getsebool >/dev/null 2>&1 && command -v setsebool >/dev/null 2>&1; then
            BOOLEAN_NAME="syslogd_can_network_connect" # Common boolean for rsyslog network access
            log "Checking SELinux boolean $BOOLEAN_NAME..."
            if getsebool "$BOOLEAN_NAME" >/dev/null 2>&1; then # Returns 0 if enabled
                log "SELinux: $BOOLEAN_NAME is already enabled."
            else
                log "SELinux: $BOOLEAN_NAME is disabled. Attempting to enable it persistently."
                if setsebool -P "$BOOLEAN_NAME" on; then
                    log "SELinux: Successfully enabled $BOOLEAN_NAME persistently."
                else
                    log "WARNING: Failed to set SELinux boolean $BOOLEAN_NAME. Manual SELinux configuration (e.g., setsebool -P $BOOLEAN_NAME on) might be needed for rsyslog network forwarding."
                fi
            fi
            log "If omprog execution for $CONCAT_EXECVE_SCRIPT_PATH is denied by SELinux, check 'ausearch -m avc -ts recent'. The script might need specific SELinux context or further policy adjustments."
        else
            log "SELinux: getsebool/setsebool commands not found. Skipping automatic SELinux boolean check. Ensure SELinux is not blocking operations."
        fi

        # Firewalld configuration
        if command -v firewall-cmd >/dev/null 2>&1; then
            if systemctl is-active --quiet firewalld; then
                log "Attempting to add firewalld rule for SIEM TCP port $SIEM_PORT..."
                firewall-cmd --permanent --add-port="$SIEM_PORT/tcp" >> "$LOG_FILE" 2>&1
                firewall-cmd --reload >> "$LOG_FILE" 2>&1 || log "WARNING: firewall-cmd --reload failed. Rule might not be active yet."
                # Verify
                if firewall-cmd --query-port="$SIEM_PORT/tcp" --permanent >/dev/null 2>&1; then # Check permanent rule
                    log "Firewalld rule for port $SIEM_PORT/tcp added to permanent configuration successfully."
                     if ! firewall-cmd --query-port="$SIEM_PORT/tcp" >/dev/null 2>&1; then # Check active rule
                        log "WARNING: Firewalld rule for port $SIEM_PORT/tcp may not be active in the running configuration despite being permanent. A reload might be needed or already attempted."
                    fi
                else
                    log "WARNING: Failed to add or verify firewalld rule for port $SIEM_PORT/tcp. Manual configuration may be needed (e.g., firewall-cmd --permanent --add-port=$SIEM_PORT/tcp && firewall-cmd --reload)."
                fi
            else
                log "Firewalld service is not active. Skipping firewalld rule addition."
            fi
        else
            log "Firewalld (firewall-cmd) not found. Skipping automatic firewall configuration for port $SIEM_PORT/tcp."
        fi
    fi
}

configure_rhel_specifics # Call RHEL specific configurations

# Diagnostic functions
diagnose_services() {
    log "Running diagnostics..."
    if systemctl is-active --quiet auditd; then log "Auditd service is active."; else
        log "WARNING: auditd is not running. Attempting to start..."; systemctl start auditd >> "$LOG_FILE" 2>&1 && log "Auditd started." || log "ERROR: Failed to start auditd."; fi
    if systemctl is-active --quiet rsyslog; then log "Rsyslog service is active."; else
        log "WARNING: rsyslog is not running. Attempting to start..."; systemctl start rsyslog >> "$LOG_FILE" 2>&1 && log "Rsyslog started." || log "ERROR: Failed to start rsyslog."; fi
    
    TEST_MESSAGE_CONTENT="Test audit-like message from setup_logging-v2.sh diagnostics $(date)"
    log "Sending test message to local3 facility: '$TEST_MESSAGE_CONTENT'"
    logger -p local3.info "$TEST_MESSAGE_CONTENT" || log "WARNING: logger command failed."
    sleep 3

    log "Checking if test message reached local system log ($LOCAL_SYSLOG_FILE)..."
    if grep -Fq "$TEST_MESSAGE_CONTENT" "$LOCAL_SYSLOG_FILE"; then
        log "Syslog test SUCCESSFUL: Test message found in $LOCAL_SYSLOG_FILE."
    else
        log "WARNING: Syslog test FAILED or DELAYED: Test message NOT found in $LOCAL_SYSLOG_FILE."
    fi
    
    log "Touching /etc/passwd to trigger 'file_passwd_changes' audit event..."
    touch /etc/passwd || log "WARNING: Test touch /etc/passwd failed."
    sleep 3

    log "Checking ausearch for 'file_passwd_changes' (uses --start today for recent events)..."
    if ausearch --start today -k file_passwd_changes --raw | grep -q 'type=SYSCALL.*file_passwd_changes'; then
        log "Audit event for 'file_passwd_changes' FOUND in audit logs (ausearch)."
        log "Checking if 'file_passwd_changes' event trace reached local syslog ($LOCAL_SYSLOG_FILE)..."
        if grep -Fq "file_passwd_changes" "$LOCAL_SYSLOG_FILE"; then
             log "Audit test SUCCESSFUL: 'file_passwd_changes' event trace found in $LOCAL_SYSLOG_FILE."
        else
             log "WARNING: Audit test PARTIALLY FAILED or DELAYED: 'file_passwd_changes' trace NOT found in $LOCAL_SYSLOG_FILE."
        fi
    else
        log "WARNING: Audit test FAILED: 'file_passwd_changes' event NOT found via ausearch. Check audit rules and auditd service."
    fi
    log "To verify SIEM forwarding: sudo tcpdump -i any host $SIEM_IP and port $SIEM_PORT -A -n"
}
 
diagnose_services
log "Setup script finished."
log "Review $LOG_FILE for detailed execution logs and any warnings."
log "Ensure the SIEM ($SIEM_IP:$SIEM_PORT) is configured to receive TCP syslog messages."
log "Verify on the SIEM or use tcpdump to confirm log flow."
exit 0
