#!/bin/bash
set -e

# ------------------------------------------------------------------------------
# Auditd and Rsyslog Configuration Script (v2 Generic with omprog)
#
# This script:
#   - Installs auditd, rsyslog, python3.
#   - Deploys a Python script to /usr/local/bin/concat_execve.py.
#   - Writes audit rules to /etc/audit/rules.d/audit.rules.
#   - Configures the audisp-syslog plugin to send audit logs to rsyslog's local3 facility.
#   - Configures rsyslog (/etc/rsyslog.d/00-siem.conf) to:
#     - Block kernel messages.
#     - For local3 messages of type EXECVE, use omprog with the Python script
#       to concatenate command arguments into a single a0 field.
#     - Forward all local3 messages (transformed or original) via TCP to the SIEM server.
#
# Usage: sudo bash setup_logging-v2.sh <SIEM_IP> <SIEM_PORT>
# ------------------------------------------------------------------------------

# Global variables
LOG_FILE="/var/log/setup_logging-v2.log" # Different log file name
SYSLOG_CONF_SIEM="/etc/rsyslog.d/00-siem.conf"
AUDIT_RULES_FILE="/etc/audit/rules.d/99-audit-siem.rules" # Using a namespaced rules file
AUDISP_PLUGIN_CONF_FILE="/etc/audisp/plugins.d/syslog.conf"
CONCAT_EXECVE_SCRIPT_PATH="/usr/local/bin/concat_execve.py"

# Ensure the log file is writable
touch "$LOG_FILE" 2>/dev/null || { echo "ERROR: Cannot write to $LOG_FILE" >&2; exit 1; }
chmod 640 "$LOG_FILE" 2>/dev/null || { echo "ERROR: Unable to set permissions on <span class="math-inline">LOG\_FILE" \>&2; exit 1; \}
\# Timestamped logging function
log\(\) \{
local message
message\="</span>(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$message" | tee -a "$LOG_FILE" >/dev/null # Only to file for less verbose stdout during normal run
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
log "Starting v2 configuration - SIEM IP: $SIEM_IP, Port: $SIEM_PORT"

# Detect distribution
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO=$ID
    VERSION_ID_NUM=<span class="math-inline">VERSION\_ID
else
DISTRO\=</span>(uname -s)
    VERSION_ID_NUM=$(uname -r)
fi

LOCAL_SYSLOG_FILE="" # For diagnostics
case "$DISTRO" in
    ubuntu|debian|kali) LOCAL_SYSLOG_FILE="/var/log/syslog";;
    rhel|centos|oracle|almalinux|rocky) LOCAL_SYSLOG_FILE="/var/log/messages";;
    *) error_exit "Unsupported distribution: $DISTRO";;
esac
log "Detected: $DISTRO $VERSION_ID_NUM, Main local syslog file for diagnostics: $LOCAL_SYSLOG_FILE"

# Package installation
install_packages() {
    log "Installing required packages (auditd, rsyslog, python3)..."
    case "$DISTRO" in
        ubuntu|debian|kali)
            apt-get update -y >> "$LOG_FILE" 2>&1 || error_exit "apt-get update failed"
            apt-get install -y auditd audispd-plugins rsyslog python3 rsyslog-omprog >> "$LOG_FILE" 2>&1 || error_exit "Package installation failed (apt-get). Ensure rsyslog-omprog is available."
            ;;
        rhel|centos|oracle|almalinux|rocky)
            if command -v dnf >/dev/null 2>&1; then # RHEL 8, 9 and derivatives
                dnf install -y audit rsyslog python3 rsyslog-omprog >> "$LOG_FILE" 2>&1 || error_exit "Package installation failed (dnf). Ensure rsyslog-omprog is available."
            else # RHEL 7 and derivatives
                # EPEL might be needed for python3 on RHEL 7
                if ! yum list installed epel-release >/dev/null 2>&1 && [[ "$VERSION_ID_NUM" == 7* ]]; then
                    log "EPEL repository is not installed on RHEL 7. Attempting to install EPEL release for Python 3..."
                    yum install -y epel-release >> "$LOG_FILE" 2>&1 || log "WARNING: Failed to install EPEL release. Python 3 might not be available or might be python2."
                    yum makecache fast >> "$LOG_FILE" 2>&1
                fi
                yum install -y audit rsyslog python3 rsyslog-omprog >> "$LOG_FILE" 2>&1 || {
                    log "ERROR: Package installation failed (yum). Python 3 or rsyslog-omprog might require EPEL repository (epel-release) on RHEL 7 or a specific rsyslog version."
                    error_exit "Package installation failed (yum)"
                }
            fi
            ;;
    esac
    log "Packages installed successfully."
}

install_packages

# Deploy concat_execve.py script
deploy_python_script() {
    log "Deploying Python script to $CONCAT_EXECVE_SCRIPT_PATH..."
    # Updated Python script content
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
        return new_line # Removed "MODIFIED: " prefix for cleaner logs
    return line

def main():
    try:
        for line_in in sys.stdin:
            processed_line = process_line(line_in.strip())
            print(processed_line)
            sys.stdout.flush()
    except Exception as e:
        print(f"concat_execve.py ERROR: {e}", file=sys.stderr)
        # if 'line_in' in locals(): print(line_in.strip()) # Optionally pass original on error

if __name__ == "__main__":
    main()
EOF
    chmod +x "$CONCAT_EXECVE_SCRIPT_PATH" || error_exit "Failed to make Python script $CONCAT_EXECVE_SCRIPT_PATH executable"
    log "<span class="math-inline">CONCAT\_EXECVE\_SCRIPT\_PATH deployed and made executable\."
\}
deploy\_python\_script
\# Configure auditd
configure\_auditd\(\) \{
log "Configuring auditd\.\.\."
mkdir \-p "</span>(dirname "$AUDIT_RULES_FILE")" || error_exit "Failed to create audit rules directory $(dirname "$AUDIT_RULES_FILE")"
    if [ -f "$AUDIT_RULES_FILE" ];then
        cp -p "<span class="math-inline">AUDIT\_RULES\_FILE" "</span>{AUDIT_RULES_FILE}.bak.$(date +%F_%T)" 2>/dev/null || log "WARNING: Could not back up $AUDIT_RULES_FILE"
    fi
    
    # Standardized Audit Rules for v2 scripts
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
-w /etc/sysconfig/network-scripts/ -p wa -k sys_rhel_net_scripts_changes
-w /etc/network/interfaces -p wa -k sys_deb_net_interfaces_changes
-w /etc/netplan/ -p wa -k sys_ubuntu_netplan_changes
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
# Executions
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_execve
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_execve
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k user_execve
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k user_execve
# Privilege Escalation and Changes
-w /bin/su -p x -k priv_su_exec
-w /usr/bin/sudo -p x -k priv_sudo_exec
-a always,exit -F arch=b64 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k priv_escalation_syscalls
-a always,exit -F arch=b32 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k priv_escalation_syscalls
# -e 2 # Make rules immutable (optional, uncomment if needed)
EOF
    chmod 640 "$AUDIT_RULES_FILE" || error_exit "Failed to set permissions on $AUDIT_RULES_FILE"
    
    log "Loading audit rules..."
    if command -v augenrules &>/dev/null; then
        augenrules --load >> "$LOG_FILE" 2>&1 || error_exit "augenrules --load failed. Check $LOG_FILE and audit daemon status."
    else
        auditctl -R "$AUDIT_RULES_FILE" >> "$LOG_FILE" 2>&1 || error_exit "auditctl -R $AUDIT_RULES_FILE failed. augenrules recommended for persistent loading."
    fi
    log "Audit rules loaded."

    systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart auditd"
    systemctl enable auditd >> "<span class="math-inline">LOG\_FILE" 2\>&1 \|\| error\_exit "Failed to enable auditd"
log "Auditd configured and restarted\."
\}
configure\_auditd
\# Configure audisp\-syslog plugin
configure\_audisp\(\) \{
log "Configuring audisp\-syslog plugin to use LOG\_LOCAL3\.\.\."
local audisp\_syslog\_binary\_path\=""
if \[ \-x "/sbin/audisp\-syslog" \]; then audisp\_syslog\_binary\_path\="/sbin/audisp\-syslog"; 
elif \[ \-x "/usr/sbin/audisp\-syslog" \]; then audisp\_syslog\_binary\_path\="/usr/sbin/audisp\-syslog";
else error\_exit "audisp\-syslog binary not found in /sbin or /usr/sbin\."; fi
mkdir \-p "</span>(dirname "$AUDISP_PLUGIN_CONF_FILE")" || error_exit "Failed to create audisp config directory"
    cat > "$AUDISP_PLUGIN_CONF_FILE" << EOF || error_exit "Failed to write audisp-syslog config to $AUDISP_PLUGIN_CONF_FILE"
active = yes
direction = out
path = $audisp_syslog_binary_path
type = always
args = LOG_LOCAL3
format = string
EOF
    chmod 640 "$AUDISP_PLUGIN_CONF_FILE" || error_exit "Failed to set permissions on $AUDISP_PLUGIN_CONF_FILE"
    log "Audisp-syslog plugin configured. Restarting auditd to apply..."
    systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart auditd after audisp configuration"
    log "Audisp-syslog configured successfully."
}
 
configure_audisp
 
# Configure rsyslog
configure_rsyslog() {
    log "Configuring rsyslog for SIEM forwarding (local3)..."
    if [ -f "$SYSLOG_CONF_SIEM" ]; then
      cp -p "<span class="math-inline">SYSLOG\_CONF\_SIEM" "</span>{SYSLOG_CONF_SIEM}.bak.$(date +%F_%T)" 2>/dev/null || log "WARNING: Could not back up $SYSLOG_CONF_SIEM"
    fi
    
    # Corrected Rsyslog configuration
    cat > "$SYSLOG_CONF_SIEM" << EOF || error_exit "Failed to write rsyslog config to $SYSLOG_CONF_SIEM"
# Load omprog module for program-based output
module(load="omprog")

# Rule to stop processing kernel messages further if they are not desired
if \$syslogfacility-text == "kern" then {
    stop # Stop processing kernel messages here
}

# Process audit logs from local3 facility
if \$syslogfacility-text == "local3" then {
    # For EXECVE messages, transform them using the Python script
    if \$msg contains "type=EXECVE" then {
        action(
            type="omprog"
            binary="$CONCAT_EXECVE_SCRIPT_PATH"
            name="TransformExecve"
            # template="" # Use default template (the message itself)
            # output="/var/log/omprog_execve_debug.log" # Uncomment for debugging omprog output
            # confirmMessages="off" # 'on' can impact performance
            # reportFailures="on" # Report if script fails
        )
    }
    # Forward ALL local3 messages (original or transformed EXECVE) to SIEM
    action(
        type="omfwd"
        target="$SIEM_IP"
        port="$SIEM_PORT"
        protocol="tcp"
        name="ForwardAuditToSIEM_local3"
        # TCP specific parameters (optional, defaults usually fine)
        # RebindInterval="10000"
        # KeepAlive="on"
        # KeepAlive.Probes="5"
        # KeepAlive.Interval="60"
        # KeepAlive.Time="300"
    )
    stop # Stop processing local3 messages further to avoid duplicates or unwanted local logging
}
EOF
    
    log "Rsyslog configuration written to $SYSLOG_CONF_SIEM"
    log "Validating rsyslog configuration..."
    if rsyslogd -N1 -f "$SYSLOG_CONF_SIEM" >> "$LOG_FILE" 2>&1; then
        log "Rsyslog configuration validation successful for $SYSLOG_CONF_SIEM."
    else
        log "WARNING: Rsyslog configuration validation reported issues for $SYSLOG_CONF_SIEM. Check $LOG_FILE."
        # Attempt to validate main config as well
        rsyslogd -N1 >> "$LOG_FILE" 2>&1 || log "WARNING: Main rsyslog configuration also has issues."
    fi

    systemctl restart rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart rsyslog"
    systemctl enable rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Failed to enable rsyslog"
    log "Rsyslog configured, restarted, and enabled."
}
 
configure_rsyslog

# Diagnostic functions
diagnose_services() {
    log "Running diagnostics..."
    if systemctl is-active --quiet auditd; then log "Auditd service is active."; else log "ERROR: auditd is not running."; fi
    if systemctl is-active --quiet rsyslog; then log "Rsyslog service is active."; else log "ERROR: rsyslog is not running."; fi
    
    local test_msg_content="Test audit-like message from setup_logging-v2.sh diagnostics $(date)"
    log "Sending test message to local3 facility: '$test_msg_content'"
    logger -p local3.info "$test_msg_content" || log "WARNING: logger command failed to send to local3."
    sleep 3

    log "Checking if test message reached local system log ($LOCAL_SYSLOG_FILE) via local3..."
    # Note: local3 might not be configured to write to $LOCAL_SYSLOG_FILE by default if we used 'stop' in 00-siem.conf
    # This test is more about checking if logger can send to local3 and if rsyslog picks it up for forwarding.
    # A more reliable test is to check SIEM or tcpdump.
    if grep -Fq "$test_msg_content" "$LOCAL_SYSLOG_FILE"; then
        log "Syslog test event (local3 to $LOCAL_SYSLOG_FILE) found. This means local3 is also writing locally."
    else
        log "Syslog test event for local3 NOT found in $LOCAL_SYSLOG_FILE. This is EXPECTED if 'stop' is used after forwarding in rsyslog config for local3. Check SIEM for the
