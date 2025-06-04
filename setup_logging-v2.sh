#!/bin/bash
set -e

# ------------------------------------------------------------------------------
# Auditd and Rsyslog Configuration Script (v2 Enhanced for RHEL)
#
# This script:
#   - Backs up relevant configuration files.
#   - Writes audit rules to /etc/audit/rules.d/99-audit-siem-rhel.rules.
#   - Configures the audisp-syslog plugin to send audit logs to rsyslog's local3 facility.
#   - Deploys a Python script to /usr/local/bin/concat_execve.py.
#   - Configures rsyslog (/etc/rsyslog.d/00-siem-rhel.conf) to:
#     - Block kernel messages.
#     - Process all messages from local3 (audit logs).
#     - For local3 messages of type EXECVE, use omprog with the Python script
#       to concatenate command arguments into a single a0 field.
#     - Forward all (potentially transformed) local3 messages via TCP to the SIEM server.
#   - Adds considerations for SELinux and Firewalld on RHEL systems.
#
# Usage: sudo bash setup-loggingv2-rhel.sh <SIEM_IP> <SIEM_PORT>
# ------------------------------------------------------------------------------

# Global variables
LOG_FILE="/var/log/setup_logging-rhel-v2.log" # Specific log file
SYSLOG_CONF_OUTPUT_FILE="/etc/rsyslog.d/00-siem-rhel.conf" # Specific rsyslog conf file
AUDIT_RULES_FILE="/etc/audit/rules.d/99-audit-siem-rhel.rules" # Specific audit rules file
AUDISP_PLUGIN_CONF_FILE="/etc/audisp/plugins.d/syslog.conf" # Standard location
CONCAT_EXECVE_SCRIPT_PATH="/usr/local/bin/concat_execve.py" # Standard location

# Ensure the log file is writable
touch "$LOG_FILE" 2>/dev/null || { echo "ERROR: Cannot write to $LOG_FILE" >&2; exit 1; }
chmod 640 "$LOG_FILE" 2>/dev/null || { echo "ERROR: Unable to set permissions on $LOG_FILE" >&2; exit 1; }

# Timestamped logging function
log() {
    local message
    message="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$message" | tee -a "$LOG_FILE" >/dev/null
    echo "$message" # Also print to stdout
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check for root privileges and parameters
[ "$EUID" -ne 0 ] && error_exit "This script must be run as root. Use sudo."
[ $# -lt 2 ] && { echo "Usage: $0 <SIEM_IP> <SIEM_PORT>" >&2; log "Usage: $0 <SIEM_IP> <SIEM_PORT>"; exit 1; }

SIEM_IP="$1"
SIEM_PORT="$2"
log "Starting RHEL v2 configuration - SIEM IP: $SIEM_IP, Port: $SIEM_PORT"

# Detect distribution
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO=$ID
    VERSION_ID_NUM=$VERSION_ID
else
    DISTRO=$(uname -s) # Fallback
    VERSION_ID_NUM=$(uname -r)
fi

LOCAL_SYSLOG_FILE="" # For diagnostics
case "$DISTRO" in
    rhel|centos|oracle|almalinux|rocky) LOCAL_SYSLOG_FILE="/var/log/messages";;
    ubuntu|debian|kali) 
        log "WARNING: This script is optimized for RHEL/derivatives. Running on $DISTRO. Some RHEL-specific steps might not apply or work as expected."
        LOCAL_SYSLOG_FILE="/var/log/syslog"
        ;;
    *) error_exit "Unsupported distribution for RHEL-specific script: $DISTRO";;
esac
log "Detected: $DISTRO $VERSION_ID_NUM, Main local syslog file for diagnostics: $LOCAL_SYSLOG_FILE"

# Package installation
install_packages() {
    log "Installing required packages (audit, rsyslog, python3, rsyslog-omprog)..."
    case "$DISTRO" in
        rhel|centos|oracle|almalinux|rocky)
            if command -v dnf >/dev/null 2>&1; then # RHEL 8, 9 and derivatives
                dnf install -y audit rsyslog python3 rsyslog-omprog >> "$LOG_FILE" 2>&1 || error_exit "Package installation failed (dnf). Ensure rsyslog-omprog is available."
            else # RHEL 7 and derivatives
                if ! yum list installed epel-release >/dev/null 2>&1 && [[ "$VERSION_ID_NUM" == 7* ]]; then
                    log "EPEL repository is not installed on RHEL 7. Attempting to install EPEL release for Python 3..."
                    yum install -y epel-release >> "$LOG_FILE" 2>&1 || log "WARNING: Failed to install EPEL release. Python 3 or rsyslog-omprog might not be available."
                    yum makecache fast >> "$LOG_FILE" 2>&1 
                fi
                yum install -y audit rsyslog python3 rsyslog-omprog >> "$LOG_FILE" 2>&1 || {
                    log "ERROR: Package installation failed with YUM. Python 3 or rsyslog-omprog might require EPEL (epel-release) on RHEL 7 or a specific rsyslog version. Check $LOG_FILE."
                    error_exit "Package installation failed (yum)"
                }
            fi
            ;;
        ubuntu|debian|kali) # Added for completeness if run on these distros
             apt-get update -y >> "$LOG_FILE" 2>&1 || error_exit "apt-get update failed"
             apt-get install -y auditd audispd-plugins rsyslog python3 rsyslog-omprog >> "$LOG_FILE" 2>&1 || error_exit "Package installation failed (apt-get). Ensure rsyslog-omprog is available."
            ;;
    esac
    log "Packages installed successfully."
}

install_packages

# Deploy concat_execve.py script
deploy_python_script() {
    log "Deploying Python script to $CONCAT_EXECVE_SCRIPT_PATH..."
    # Python script content (same as in setup_logging-v2.sh)
    cat > "$CONCAT_EXECVE_SCRIPT_PATH" << 'EOF'
#!/usr/bin/env python3
import sys
import re

def process_line(line):
    if "type=EXECVE" not in line:
        return line
    args = re.findall(r'a\d+="([^"]*)"', line)
    if args:
        combined_command = " ".join(args)
        escaped_combined_command = combined_command.replace('"', '\\"')
        new_line = re.sub(r'a\d+="(?:[^"\\]|\\.)*"\s*', '', line).strip()
        if new_line and not new_line.endswith(" "):
            new_line += " "
        new_line += 'a0="' + escaped_combined_command + '"'
        return new_line
    return line

def main():
    try:
        for line_in in sys.stdin:
            processed_line = process_line(line_in.strip())
            print(processed_line)
            sys.stdout.flush()
    except Exception as e:
        print(f"concat_execve.py ERROR: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
EOF
    chmod +x "$CONCAT_EXECVE_SCRIPT_PATH" || error_exit "Failed to make Python script $CONCAT_EXECVE_SCRIPT_PATH executable"
    log "$CONCAT_EXECVE_SCRIPT_PATH deployed and made executable."
}

deploy_python_script

# Configure auditd
configure_auditd() {
    log "Configuring auditd..."
    # Backup auditd.conf (original script skipped direct mods, which is fine)
    # if [ -f "/etc/audit/auditd.conf" ]; then
    #     cp -p "/etc/audit/auditd.conf" "/etc/audit/auditd.conf.bak.$(date +%F_%T)" 2>/dev/null || log "WARNING: Could not back up /etc/audit/auditd.conf"
    # fi
    # log "Skipping direct modifications to /etc/audit/auditd.conf." # Retain this if no changes needed
    
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")" || error_exit "Failed to create audit rules directory $(dirname "$AUDIT_RULES_FILE")"
    if [ -f "$AUDIT_RULES_FILE" ];then
        cp -p "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.bak.$(date +%F_%T)" 2>/dev/null || log "WARNING: Could not back up $AUDIT_RULES_FILE"
    fi
    
    # Corrected and comprehensive audit rules for RHEL v2
    # This addresses the augenrules error by using auid!=-1 and consistent keying.
    cat > "$AUDIT_RULES_FILE" << 'EOF'
-D
-b 8192
-f 1
# Self-auditing
-w /etc/audit/ -p wa -k audit_config_changes
-w /etc/libaudit.conf -p wa -k audit_config_changes
-w /etc/audisp/ -p wa -k audit_config_changes
-w /sbin/auditctl -p x -k audit_tool_usage
-w /sbin/auditd -p x -k audit_tool_usage
-w /var/log/audit/ -p rwa -k audit_log_access
# Identity and Access Management
-w /etc/passwd -p wa -k iam_passwd_changes
-w /etc/shadow -p wa -k iam_shadow_changes
-w /etc/group -p wa -k iam_group_changes
-w /etc/gshadow -p wa -k iam_gshadow_changes
-w /etc/sudoers -p wa -k iam_sudoers_changes
-w /etc/sudoers.d/ -p wa -k iam_sudoers_d_changes
-w /etc/login.defs -p wa -k iam_login_defs_changes
-w /etc/security/opasswd -p wa -k iam_opasswd_changes
-w /var/log/faillog -p wa -k iam_faillog_access
-w /var/log/lastlog -p wa -k iam_lastlog_access
-w /etc/pam.d/ -p wa -k iam_pam_changes
# System and Network Configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k sys_net_config_changes
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k sys_net_config_changes
-w /etc/hosts -p wa -k sys_hosts_file_changes
-w /etc/sysconfig/network-scripts/ -p wa -k sys_rhel_net_scripts_changes # RHEL specific
-w /etc/network/interfaces -p wa -k sys_deb_net_interfaces_changes # Debian/Ubuntu
-w /etc/netplan/ -p wa -k sys_ubuntu_netplan_changes # Ubuntu with netplan
# System State Changes
-w /sbin/shutdown -p x -k sys_state_shutdown
-w /sbin/poweroff -p x -k sys_state_poweroff
-w /sbin/reboot -p x -k sys_state_reboot
-w /sbin/halt -p x -k sys_state_halt
# Kernel Module Changes
-a always,exit -F path=/sbin/insmod -F perm=x -F auid>=1000 -F auid!=-1 -k kernel_mod_insmod
-a always,exit -F path=/sbin/rmmod -F perm=x -F auid>=1000 -F auid!=-1 -k kernel_mod_rmmod
-a always,exit -F path=/sbin/modprobe -F perm=x -F auid>=1000 -F auid!=-1 -k kernel_mod_modprobe
-w /etc/modprobe.conf -p wa -k kernel_mod_conf_changes
-w /etc/modprobe.d/ -p wa -k kernel_mod_conf_d_changes
# Executions (Corrected keys for consistency and to avoid augenrules issue)
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_execve
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_execve
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k user_execve
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k user_execve
# Privilege Escalation and Changes
-w /bin/su -p x -k priv_su_exec
-w /usr/bin/sudo -p x -k priv_sudo_exec
-a always,exit -F arch=b64 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k priv_escalation_syscalls
-a always,exit -F arch=b32 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k priv_escalation_syscalls
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F a1&0111 -F auid>=1000 -F auid!=-1 -k priv_perm_change_exec_sgid
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F a1&0111 -F auid>=1000 -F auid!=-1 -k priv_perm_change_exec_sgid
# Suspicious Utilities (examples, can be noisy)
-w /usr/bin/wget -p x -k susp_wget_usage
-w /usr/bin/curl -p x -k susp_curl_usage
-w /bin/nc -p x -k susp_netcat_usage
-w /usr/bin/ncat -p x -k susp_ncat_usage
# -e 2 # Make rules immutable (optional)
EOF
    chmod 640 "$AUDIT_RULES_FILE" || error_exit "Failed to set permissions on $AUDIT_RULES_FILE"
    
    log "Loading audit rules via augenrules..."
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >> "$LOG_FILE" 2>&1 || error_exit "augenrules --load failed. Check $LOG_FILE and audit daemon status for errors related to $AUDIT_RULES_FILE."
    else
        # Fallback if augenrules isn't there, though it should be on RHEL systems
        auditctl -R "$AUDIT_RULES_FILE" >> "$LOG_FILE" 2>&1 || error_exit "auditctl -R $AUDIT_RULES_FILE failed. augenrules is highly recommended for persistent rule loading."
    fi
    log "Audit rules loaded."

    systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart auditd"
    systemctl enable auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable auditd"
    log "Auditd configured, rules loaded, and service restarted/enabled."
}
 
configure_auditd
 
# Configure audisp-syslog plugin
configure_audisp() {
    log "Configuring audisp-syslog plugin to use LOG_LOCAL3..."
    local audisp_syslog_binary_path=""
    if [ -x "/sbin/audisp-syslog" ]; then audisp_syslog_binary_path="/sbin/audisp-syslog"; 
    elif [ -x "/usr/sbin/audisp-syslog" ]; then audisp_syslog_binary_path="/usr/sbin/audisp-syslog"; # More common on Debian-likes
    else error_exit "audisp-syslog binary not found in /sbin or /usr/sbin."; fi
    
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
    log "Audisp-syslog plugin configured to use LOG_LOCAL3. Restarting auditd..."
    systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart auditd after audisp configuration"
    log "Audisp-syslog configured successfully."
}
 
configure_audisp
 
# Configure rsyslog (Rsyslog logic is sound from original rhel script)
configure_rsyslog() {
    log "Configuring rsyslog for SIEM (local3 with omprog for EXECVE)..."
    if [ -f "$SYSLOG_CONF_OUTPUT_FILE" ]; then
      cp -p "$SYSLOG_CONF_OUTPUT_FILE" "${SYSLOG_CONF_OUTPUT_FILE}.bak.$(date +%F_%T)" 2>/dev/null || log "WARNING: Could not back up $SYSLOG_CONF_OUTPUT_FILE"
    fi
    
    cat > "$SYSLOG_CONF_OUTPUT_FILE" << EOF || error_exit "Failed to write rsyslog configuration to $SYSLOG_CONF_OUTPUT_FILE"
# Load omprog module for program-based output
module(load="omprog")

# Rule to stop processing kernel messages further
if \$syslogfacility-text == "kern" then {
    stop
}

# Process audit logs from local3 facility
if \$syslogfacility-text == "local3" then {
    # For EXECVE messages, transform them using the Python script
    if \$msg contains "type=EXECVE" then {
        action(
            type="omprog"
            binary="$CONCAT_EXECVE_SCRIPT_PATH"
            name="TransformExecve_RHEL" # Unique name for action
            # template="" # Use default template (the message itself)
            # output="/var/log/omprog_execve_rhel_debug.log" # Uncomment for debugging omprog output
            # useTransactions="on" # Can provide atomicity but may impact performance; test if needed. Default off.
            # confirmMessages="off" 
            # reportFailures="on" 
        )
    }
    # Forward ALL local3 messages (original or transformed EXECVE) to SIEM
    action(
        type="omfwd"
        target="$SIEM_IP"
        port="$SIEM_PORT"
        protocol="tcp"
        name="ForwardAuditToSIEM_RHEL_local3"
        # TCP specific parameters (optional)
        # RebindInterval="10000"
        # KeepAlive="on"
    )
    stop # Stop processing local3 messages further
}
EOF
    
    log "Rsyslog configuration written to $SYSLOG_CONF_OUTPUT_FILE"
    log "Validating rsyslog configuration..."
    if rsyslogd -N1 -f "$SYSLOG_CONF_OUTPUT_FILE" >> "$LOG_FILE" 2>&1; then
        log "Rsyslog configuration validation successful for $SYSLOG_CONF_OUTPUT_FILE."
    else
        log "WARNING: Rsyslog configuration validation reported issues for $SYSLOG_CONF_OUTPUT_FILE. Check $LOG_FILE."
        rsyslogd -N1 >> "$LOG_FILE" 2>&1 || log "WARNING: Main rsyslog configuration also has issues."
    fi

    systemctl restart rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart rsyslog"
    systemctl enable rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable rsyslog"
    log "Rsyslog configured, restarted, and enabled."
}
 
configure_rsyslog

# Configure SELinux and Firewall for RHEL/CentOS/Oracle/Alma/Rocky
configure_rhel_specifics() {
    if [[ "$DISTRO" == "rhel" || "$DISTRO" == "centos" || "$DISTRO" == "oracle" || "$DISTRO" == "almalinux" || "$DISTRO" == "rocky" ]]; then
        log "Performing RHEL-specific configurations (SELinux, Firewall)..."
        # SELinux configuration for rsyslog network connect
        if command -v getsebool >/dev/null 2>&1 && command -v setsebool >/dev/null 2>&1; then
            local selinux_bool_syslog_net="syslogd_can_network_connect"
            log "Checking SELinux boolean $selinux_bool_syslog_net..."
            if getsebool "$selinux_bool_syslog_net" | grep -q "--> on$"; then
                log "SELinux: $selinux_bool_syslog_net is already enabled."
            else
                log "SELinux: $selinux_bool_syslog_net is disabled. Attempting to enable it persistently."
                if setsebool -P "$selinux_bool_syslog_net" on; then
                    log "SELinux: Successfully enabled $selinux_bool_syslog_net persistently."
                else
                    log "WARNING: Failed to set SELinux boolean $selinux_bool_syslog_net. Manual SELinux config (setsebool -P $selinux_bool_syslog_net on) might be needed for rsyslog network forwarding."
                fi
            fi
            # SELinux for omprog execution (Python script)
            # This might require specific policy if script is denied. Common contexts are /usr/bin, /usr/sbin.
            # /usr/local/bin might have different default labeling.
            # Check 'ls -Z $CONCAT_EXECVE_SCRIPT_PATH' and 'ausearch -m avc -ts recent' if omprog fails.
            # A common boolean for allowing daemons to execute scripts is 'daemons_enable_cluster_mode', but this is broad.
            # Custom policy or 'chcon -t syslogd_script_exec_t $CONCAT_EXECVE_SCRIPT_PATH' (if type exists) might be needed.
            log "SELinux: If omprog execution of $CONCAT_EXECVE_SCRIPT_PATH is denied, check 'ausearch -m avc -ts recent'. The script might need 'chcon -t syslogd_script_exec_t $CONCAT_EXECVE_SCRIPT_PATH' or a custom SELinux policy module."
        else
            log "SELinux: getsebool/setsebool commands not found. Skipping automatic SELinux boolean check."
        fi

        # Firewalld configuration
        if command -v firewall-cmd >/dev/null 2>&1; then
            if systemctl is-active --quiet firewalld; then
                log "Firewalld is active. Attempting to add rule for SIEM TCP port $SIEM_PORT..."
                if firewall-cmd --query-port="$SIEM_PORT/tcp" --permanent >/dev/null 2>&1; then
                    log "Firewalld: Port $SIEM_PORT/tcp is already in permanent configuration."
                else
                    firewall-cmd --permanent --add-port="$SIEM_PORT/tcp" >> "$LOG_FILE" 2>&1 || log "WARNING: firewall-cmd --permanent --add-port failed."
                fi
                # Reload is needed to apply permanent rules to runtime, but also to activate newly added permanent rule.
                firewall-cmd --reload >> "$LOG_FILE" 2>&1 || log "WARNING: firewall-cmd --reload failed. Rule might not be active yet. Check 'firewall-cmd --list-ports'."
                if firewall-cmd --query-port="$SIEM_PORT/tcp" >/dev/null 2>&1; then
                    log "Firewalld: Port $SIEM_PORT/tcp is now active in the running configuration."
                else
                    log "WARNING: Firewalld: Port $SIEM_PORT/tcp may NOT be active. Check 'firewall-cmd --list-ports' and firewall logs."
                fi
            else
                log "Firewalld service is not active. Skipping firewalld rule addition."
            fi
        else
            log "Firewalld (firewall-cmd) not found. Skipping automatic firewall configuration for port $SIEM_PORT/tcp."
        fi
    fi
}

configure_rhel_specifics

# Diagnostic functions
diagnose_services() {
    log "Running diagnostics..."
    if systemctl is-active --quiet auditd; then log "Auditd service is active."; else log "ERROR: auditd is not running."; fi
    if systemctl is-active --quiet rsyslog; then log "Rsyslog service is active."; else log "ERROR: rsyslog is not running."; fi
    
    local test_msg_content="Test RHEL audit-like message from setup-loggingv2-rhel.sh diagnostics $(date)"
    log "Sending test message to local3 facility: '$test_msg_content'"
    logger -p local3.info "$test_msg_content" || log "WARNING: logger command failed to send to local3."
    sleep 3

    log "Checking if test message reached local system log ($LOCAL_SYSLOG_FILE) via local3..."
    if grep -Fq "$test_msg_content" "$LOCAL_SYSLOG_FILE"; then
        log "Syslog test event (local3 to $LOCAL_SYSLOG_FILE) found."
    else
        log "Syslog test event for local3 NOT found in $LOCAL_SYSLOG_FILE. This is EXPECTED if 'stop' is used after forwarding in rsyslog. Check SIEM."
    fi
    
    log "Touching /etc/passwd to trigger 'iam_passwd_changes' audit event..."
    touch /etc/passwd || log "WARNING: Test 'touch /etc/passwd' failed."
    sleep 3

    log "Checking ausearch for 'iam_passwd_changes' (uses --start today for recent events)..."
    if ausearch --start today -k iam_passwd_changes --raw | grep -q 'type=SYSCALL.*key="iam_passwd_changes"'; then
        log "Audit event for 'iam_passwd_changes' FOUND in local audit logs (ausearch)."
    else
        log "WARNING: Audit event 'iam_passwd_changes' NOT found via ausearch. Check audit rules and auditd service."
    fi
    log "To verify SIEM forwarding: sudo tcpdump -i any host $SIEM_IP and port $SIEM_PORT -A -n"
    log "Check for concat_execve.py errors in rsyslog logs or the omprog debug log file (if enabled in rsyslog config)."
}
 
diagnose_services
log "Setup script (RHEL v2) finished."
log "Review $LOG_FILE for detailed execution logs and any warnings."
log "Ensure the SIEM ($SIEM_IP:$SIEM_PORT) is configured to receive TCP syslog messages from facility local3."
exit 0
