# Manual QRadar Log Forwarding Setup

This document provides instructions for manually configuring Linux systems to forward audit logs to IBM QRadar SIEM. These instructions are an alternative to using the provided installer scripts.

## Introduction

The goal of this setup is to configure `auditd` to collect system audit events, `rsyslog` to forward these events to QRadar, and a Python script to parse and format the logs for better readability and analysis in QRadar.

This guide is divided into two main sections:
*   **Debian/Ubuntu Setup**
*   **RHEL/CentOS/Rocky/AlmaLinux Setup**

Please follow the instructions for your specific distribution.

## Prerequisites

*   **Root Access**: You must have `sudo` or `root` privileges to complete these steps.
*   **QRadar Server**: You must have a QRadar server with a configured log source to receive the forwarded logs.
*   **Network Connectivity**: The system you are configuring must be able to reach the QRadar server on the specified IP address and port.

---

## Debian/Ubuntu Manual Setup

These instructions apply to Debian 9+ and Ubuntu 18.04+.

### 1. Install Prerequisites

First, update your package list and install the necessary packages:

```bash
sudo apt-get update
sudo apt-get install -y auditd audispd-plugins rsyslog python3
```

### 2. Configure Auditd Rules

Create a new audit rules file for QRadar:

```bash
sudo nano /etc/audit/rules.d/99-qradar.rules
```

Copy and paste the following rules into the file:

```
# QRadar Audit Rules
-D
-b 16384
-f 1
-r 150
-i
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k credential_access
-w /etc/group -p wa -k identity_changes
-w /etc/gshadow -p wa -k credential_access
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation
-w /etc/pam.d/ -p wa -k authentication_config
-w /etc/security/ -p wa -k security_config
-w /etc/login.defs -p wa -k login_config
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/ssh_config -p wa -k ssh_config
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/*/.ssh/ -p wa -k ssh_keys
-a always,exit -F arch=b64 -S execve -k root_commands
-a always,exit -F arch=b32 -S execve -k root_commands
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/pkexec -p x -k privilege_escalation
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_config
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/hostname -p wa -k network_config
-w /etc/network/interfaces -p wa -k network_config
-w /etc/netplan/ -p wa -k network_config
-w /etc/NetworkManager/ -p wa -k network_config
-w /sbin/shutdown -p x -k system_shutdown
-w /sbin/poweroff -p x -k system_shutdown
-w /sbin/reboot -p x -k system_shutdown
-w /sbin/halt -p x -k system_shutdown
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership
-w /usr/bin/wget -p x -k network_tools
-w /usr/bin/curl -p x -k network_tools
-w /bin/nc -p x -k network_tools
-w /usr/bin/ncat -p x -k network_tools
-w /usr/bin/netcat -p x -k network_tools
-w /usr/bin/ssh -p x -k remote_access
-w /usr/bin/scp -p x -k remote_access
-w /usr/bin/sftp -p x -k remote_access
-w /usr/bin/rsync -p x -k remote_access
-w /usr/bin/whoami -p x -k system_discovery
-w /usr/bin/id -p x -k system_discovery
-w /usr/bin/w -p x -k system_discovery
-w /usr/bin/who -p x -k system_discovery
-w /etc/cron.d/ -p wa -k scheduled_tasks
-w /etc/cron.daily/ -p wa -k scheduled_tasks
-w /etc/cron.hourly/ -p wa -k scheduled_tasks
-w /etc/cron.monthly/ -p wa -k scheduled_tasks
-w /etc/cron.weekly/ -p wa -k scheduled_tasks
-w /var/spool/cron/ -p wa -k scheduled_tasks
-w /etc/crontab -p wa -k scheduled_tasks
-w /etc/systemd/system/ -p wa -k systemd_services
-w /lib/systemd/system/ -p wa -k systemd_services
-w /usr/lib/systemd/system/ -p wa -k systemd_services
-a always,exit -F arch=b64 -S init_module,delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module,delete_module -k kernel_modules
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-w /var/log/auth.log -p wa -k log_modification
-w /var/log/syslog -p wa -k log_modification
-w /var/log/audit/ -p wa -k audit_log_modification
-w /etc/audit/ -p wa -k audit_config
-w /sbin/auditctl -p x -k audit_tools
-w /sbin/auditd -p x -k audit_tools
```

### 3. Configure Audispd to Forward to Syslog

Edit the `syslog.conf` file to enable forwarding of audit events to syslog:

```bash
# For Ubuntu 20.04+ and Debian 10+
sudo nano /etc/audit/plugins.d/syslog.conf

# For older versions
sudo nano /etc/audisp/plugins.d/syslog.conf
```

Ensure the file contains the following:

```
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_LOCAL3
format = string
```

### 4. Deploy the Python Parser Script

Create the Python script to parse and format the `EXECVE` logs:

```bash
sudo nano /usr/local/bin/qradar_execve_parser.py
```

Copy and paste the following code into the file:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import re
import signal

class ExecveParser:
    def __init__(self):
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    def _signal_handler(self, signum, frame):
        sys.exit(0)

    def process_execve_line(self, line):
        if "type=EXECVE" not in line:
            return line

        if "proctitle=" in line or "PROCTITLE" in line:
            return None

        try:
            args_pattern = r'a(\d+)="([^"]*)"'
            args_matches = re.findall(args_pattern, line)

            if not args_matches:
                return line

            args_dict = {int(index): value for index, value in args_matches}

            sorted_args = sorted(args_dict.items())
            combined_command = " ".join(arg[1] for arg in sorted_args)

            cleaned_line = re.sub(r'a\d+="[^"]*"\s*', '', line).strip()
            cleaned_line = re.sub(r'argc=\d+\s*', '', cleaned_line).strip()

            processed_line = f"{cleaned_line} cmd=\"{combined_command}\""
            return processed_line

        except Exception:
            return line

    def run(self):
        try:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    processed_line = self.process_execve_line(line)
                    if processed_line is not None:
                        print(processed_line, flush=True)
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        except Exception:
            sys.exit(1)

if __name__ == "__main__":
    parser = ExecveParser()
    parser.run()
```

Make the script executable:

```bash
sudo chmod +x /usr/local/bin/qradar_execve_parser.py
```

### 5. Configure Rsyslog Forwarding

Create a new rsyslog configuration file for QRadar:

```bash
sudo nano /etc/rsyslog.d/99-qradar.conf
```

Copy and paste the following configuration into the file, replacing `<QRADAR_IP>` and `<QRADAR_PORT>` with your QRadar server's IP address and port:

```
# QRadar Log Forwarding Configuration
module(load="omprog")

# QRadar-compatible template (RFC 3339 time stamp)
template(name="QRadarFormat" type="string"
         string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name%: %msg%\n")

# Only process messages from facility local3
if $syslogfacility-text == 'local3' then {

    # Process EXECVE events with parser to prevent duplicates
    if $msg contains 'type=EXECVE' then {
        action(
            type="omprog"
            binary="/usr/local/bin/qradar_execve_parser.py"
            template="RSYSLOG_TraditionalFileFormat"
            forceSingleInstance="on"
            queue.workerThreads="1"
        )
    }
    
    # Forward all audit logs to QRadar
    action(
        type="omfwd"
        target="<QRADAR_IP>"
        port="<QRADAR_PORT>"
        protocol="tcp"
        template="QRadarFormat"
        
        # Reliable async queue with reasonable limits
        queue.type="linkedlist"
        queue.size="50000"
        queue.maxdiskspace="2g"
        queue.saveOnShutdown="on"
        queue.highWatermark="40000"
        queue.lowWatermark="10000"
        queue.discardMark="45000"
        queue.discardSeverity="4"
        action.resumeRetryCount="100"
        action.resumeInterval="30"
    )

    stop    # Prevent further rule processing
}
```

### 6. Restart Services

Restart the `auditd` and `rsyslog` services to apply the changes:

```bash
sudo systemctl restart auditd
sudo systemctl restart rsyslog
```

### 7. Verify the Setup

Verify the configuration and test log forwarding:

```bash
# Check rsyslog configuration syntax
sudo rsyslogd -N1

# Test the parser script
echo 'type=EXECVE msg=audit(123:456): argc=3 a0="ls" a1="-la" a2="/tmp"' | sudo /usr/local/bin/qradar_execve_parser.py

# Send test logs
logger -p local3.info "Test QRadar forwarding"
logger -p local3.info 'type=EXECVE msg=audit(1234:567): argc=3 a0="test" a1="-la" a2="/tmp"'

# Monitor traffic to QRadar
sudo tcpdump -i any host <QRADAR_IP> and port <QRADAR_PORT> -A -n
```

---

## RHEL/CentOS/Rocky/AlmaLinux Manual Setup

These instructions apply to RHEL 7+, CentOS 7+, and other RHEL-based distributions.

### 1. Install Prerequisites

First, install the necessary packages using `yum` or `dnf`:

```bash
# For RHEL 7/CentOS 7
sudo yum install -y audit audispd-plugins rsyslog python3

# For RHEL 8+ and derivatives
sudo dnf install -y audit rsyslog python3
```

### 2. Configure Auditd Rules

Create a new audit rules file for QRadar:

```bash
sudo nano /etc/audit/rules.d/99-qradar.rules
```

Copy and paste the following rules into the file:

```
# QRadar Audit Rules
-D
-b 16384
-f 1
-r 150
-i
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k credential_access
-w /etc/group -p wa -k identity_changes
-w /etc/gshadow -p wa -k credential_access
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation
-w /etc/pam.d/ -p wa -k authentication_config
-w /etc/security/ -p wa -k security_config
-w /etc/login.defs -p wa -k login_config
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/ssh_config -p wa -k ssh_config
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/*/.ssh/ -p wa -k ssh_keys
-a always,exit -F arch=b64 -S execve -k root_commands
-a always,exit -F arch=b32 -S execve -k root_commands
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/pkexec -p x -k privilege_escalation
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_config
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/hostname -p wa -k network_config
-w /etc/sysconfig/network -p wa -k network_config
-w /etc/sysconfig/network-scripts/ -p wa -k network_config
-w /etc/NetworkManager/ -p wa -k network_config
-w /sbin/shutdown -p x -k system_shutdown
-w /sbin/poweroff -p x -k system_shutdown
-w /sbin/reboot -p x -k system_shutdown
-w /sbin/halt -p x -k system_shutdown
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k file_ownership
-w /usr/bin/wget -p x -k network_tools
-w /usr/bin/curl -p x -k network_tools
-w /bin/nc -p x -k network_tools
-w /usr/bin/ncat -p x -k network_tools
-w /usr/bin/netcat -p x -k network_tools
-w /usr/bin/ssh -p x -k remote_access
-w /usr/bin/scp -p x -k remote_access
-w /usr/bin/sftp -p x -k remote_access
-w /usr/bin/rsync -p x -k remote_access
-w /usr/bin/whoami -p x -k system_discovery
-w /usr/bin/id -p x -k system_discovery
-w /usr/bin/w -p x -k system_discovery
-w /usr/bin/who -p x -k system_discovery
-w /etc/cron.d/ -p wa -k scheduled_tasks
-w /etc/cron.daily/ -p wa -k scheduled_tasks
-w /etc/cron.hourly/ -p wa -k scheduled_tasks
-w /etc/cron.monthly/ -p wa -k scheduled_tasks
-w /etc/cron.weekly/ -p wa -k scheduled_tasks
-w /var/spool/cron/ -p wa -k scheduled_tasks
-w /etc/crontab -p wa -k scheduled_tasks
-w /etc/systemd/system/ -p wa -k systemd_services
-w /lib/systemd/system/ -p wa -k systemd_services
-w /usr/lib/systemd/system/ -p wa -k systemd_services
-a always,exit -F arch=b64 -S init_module,delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module,delete_module -k kernel_modules
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-w /var/log/messages -p wa -k log_modification
-w /var/log/secure -p wa -k log_modification
-w /var/log/audit/ -p wa -k audit_log_modification
-w /etc/audit/ -p wa -k audit_config
-w /sbin/auditctl -p x -k audit_tools
-w /sbin/auditd -p x -k audit_tools
```

### 3. Configure Audispd to Forward to Syslog

Edit the `syslog.conf` file to enable forwarding of audit events to syslog:

```bash
sudo nano /etc/audit/plugins.d/syslog.conf
```

Ensure the file contains the following:

```
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_LOCAL3
format = string
```

### 4. Deploy the Python Parser Script

Create the Python script to parse and format the `EXECVE` logs:

```bash
sudo nano /usr/local/bin/qradar_execve_parser.py
```

Copy and paste the following code into the file:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import re
import signal

class ExecveParser:
    def __init__(self):
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    def _signal_handler(self, signum, frame):
        sys.exit(0)

    def process_execve_line(self, line):
        if "type=EXECVE" not in line:
            return line

        if "proctitle=" in line or "PROCTITLE" in line:
            return None

        try:
            args_pattern = r'a(\d+)="([^"]*)"'
            args_matches = re.findall(args_pattern, line)

            if not args_matches:
                return line

            args_dict = {int(index): value for index, value in args_matches}

            sorted_args = sorted(args_dict.items())
            combined_command = " ".join(arg[1] for arg in sorted_args)

            cleaned_line = re.sub(r'a\d+="[^"]*"\s*', '', line).strip()
            cleaned_line = re.sub(r'argc=\d+\s*', '', cleaned_line).strip()

            processed_line = f"{cleaned_line} cmd=\"{combined_command}\""
            return processed_line

        except Exception:
            return line

    def run(self):
        try:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    processed_line = self.process_execve_line(line)
                    if processed_line is not None:
                        print(processed_line, flush=True)
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        except Exception:
            sys.exit(1)

if __name__ == "__main__":
    parser = ExecveParser()
    parser.run()
```

Make the script executable:

```bash
sudo chmod +x /usr/local/bin/qradar_execve_parser.py
```

### 5. Configure SELinux

If SELinux is enabled on your system, configure the necessary permissions:

```bash
# Allow rsyslog to make network connections
sudo setsebool -P rsyslog_can_network_connect on

# Set proper context for the Python script
sudo semanage fcontext -a -t bin_t "/usr/local/bin/qradar_execve_parser.py"
sudo restorecon -v /usr/local/bin/qradar_execve_parser.py

# Allow rsyslog to execute external programs
sudo setsebool -P nis_enabled 1

# If additional permissions are needed, create a custom policy
# Check for denials first
sudo ausearch -c 'rsyslogd' --raw | audit2allow -M my-rsyslogd
# Apply the policy if needed
sudo semodule -i my-rsyslogd.pp
```

### 6. Configure FirewallD

If FirewallD is enabled and you have strict outbound rules, allow traffic to QRadar:

```bash
# For most environments, outbound traffic is allowed by default
# If you have strict outbound rules, add this:
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -d <QRADAR_IP> -p tcp --dport <QRADAR_PORT> -j ACCEPT
sudo firewall-cmd --reload
```

### 7. Configure Rsyslog Forwarding

Create a new rsyslog configuration file for QRadar:

```bash
sudo nano /etc/rsyslog.d/99-qradar.conf
```

Copy and paste the following configuration into the file, replacing `<QRADAR_IP>` and `<QRADAR_PORT>` with your QRadar server's IP address and port:

```
# QRadar Log Forwarding Configuration
module(load="omprog")

# QRadar-compatible template (RFC 3339 time stamp)
template(name="QRadarFormat" type="string"
         string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name%: %msg%\n")

# Only process messages from facility local3
if $syslogfacility-text == 'local3' then {

    # Process EXECVE events with parser to prevent duplicates
    if $msg contains 'type=EXECVE' then {
        action(
            type="omprog"
            binary="/usr/local/bin/qradar_execve_parser.py"
            template="RSYSLOG_TraditionalFileFormat"
            forceSingleInstance="on"
            queue.workerThreads="1"
        )
    }
    
    # Forward all audit logs to QRadar
    action(
        type="omfwd"
        target="<QRADAR_IP>"
        port="<QRADAR_PORT>"
        protocol="tcp"
        template="QRadarFormat"
        
        # Reliable async queue with reasonable limits
        queue.type="linkedlist"
        queue.size="50000"
        queue.maxdiskspace="2g"
        queue.saveOnShutdown="on"
        queue.highWatermark="40000"
        queue.lowWatermark="10000"
        queue.discardMark="45000"
        queue.discardSeverity="4"
        action.resumeRetryCount="100"
        action.resumeInterval="30"
    )

    stop    # Prevent further rule processing
}
```

### 8. Restart Services

Restart the `auditd` and `rsyslog` services to apply the changes:

```bash
sudo systemctl restart auditd
sudo systemctl restart rsyslog
```

### 9. Verify the Setup

Verify the configuration and test log forwarding:

```bash
# Check rsyslog configuration syntax
sudo rsyslogd -N1

# Test the parser script
echo 'type=EXECVE msg=audit(123:456): argc=3 a0="ls" a1="-la" a2="/tmp"' | sudo /usr/local/bin/qradar_execve_parser.py

# Send test logs
logger -p local3.info "Test QRadar forwarding"
logger -p local3.info 'type=EXECVE msg=audit(1234:567): argc=3 a0="test" a1="-la" a2="/tmp"'

# Monitor traffic to QRadar
sudo tcpdump -i any host <QRADAR_IP> and port <QRADAR_PORT> -A -n
```

## Troubleshooting

### Check Service Status
```bash
# Check auditd status
sudo systemctl status auditd

# Check rsyslog status
sudo systemctl status rsyslog

# View rsyslog errors
sudo journalctl -u rsyslog -f
```

### Debug Rsyslog Configuration
```bash
# Run rsyslog in debug mode
sudo rsyslogd -dn 2>&1 | grep -i "qradar\|omprog\|omfwd\|local3"

# Check rsyslog statistics
sudo pkill -USR1 rsyslogd && sudo tail -f /var/log/messages | grep rsyslogd-pstats
```

### Common Issues

1. **SELinux Denials**: Check `/var/log/audit/audit.log` for denials and create custom policies as needed
2. **Network Connectivity**: Ensure the system can reach QRadar on the specified port
3. **Parser Errors**: Test the parser script manually with sample EXECVE logs
4. **Queue Overflow**: Adjust queue sizes based on your log volume

## Performance Tuning

For high-volume environments, consider these optimizations:

### Audit Buffer Size
```bash
# In /etc/audit/rules.d/99-qradar.rules, increase buffer size:
-b 32768  # or higher for very busy systems
```

### Rsyslog Global Settings
```bash
# Add to /etc/rsyslog.conf:
$MaxMessageSize 64k
$WorkDirectory /var/spool/rsyslog
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
```

### Log Rotation
```bash
# Create /etc/logrotate.d/qradar-audit:
/var/log/audit/audit.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0600 root root
    postrotate
        /usr/bin/pkill -HUP rsyslogd > /dev/null 2>&1 || true
    endscript
}
```

## Notes

- The Python parser script formats EXECVE logs for better readability in QRadar
- All audit events are forwarded to QRadar, with EXECVE events being pre-processed
- The configuration uses reliable queuing to prevent log loss during network issues
- Adjust queue parameters based on your environment's log volume and network reliability
