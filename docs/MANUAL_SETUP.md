# Manual QRadar Log Forwarding Setup

This document provides instructions for manually configuring Linux systems to forward audit logs to IBM QRadar SIEM. These instructions are an alternative to using the provided installer scripts.

## Introduction

The goal of this setup is to configure `auditd` to collect system audit events and `rsyslog` to forward these events to QRadar.

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
sudo apt-get install -y auditd audispd-plugins rsyslog
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

### 4. Configure Rsyslog Forwarding

Create a new rsyslog configuration file for QRadar:

```bash
sudo nano /etc/rsyslog.d/99-qradar.conf
```

Copy and paste the following configuration into the file, replacing `<QRADAR_IP>` and `<QRADAR_PORT>` with your QRadar server's IP address and port:

```
# QRadar Log Forwarding Configuration
template(name="QRadarFormat" type="string" string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name%: %msg%\\n")

if $syslogfacility-text == 'local3' then {
    action(
        type="omfwd"
        target="<QRADAR_IP>"
        port="<QRADAR_PORT>"
        protocol="tcp"
        template="QRadarFormat"
        queue.type="linkedlist"
        queue.size="50000"
        action.resumeRetryCount="-1"
    )
    stop
}
```

### 5. Restart Services

Restart the `auditd` and `rsyslog` services to apply the changes:

```bash
sudo systemctl restart auditd
sudo systemctl restart rsyslog
```

### 6. Verify the Setup

You can verify the setup by checking the logs on your QRadar server or by using `tcpdump` to monitor the traffic to your QRadar server:

```bash
sudo tcpdump -i any host <QRADAR_IP> and port <QRADAR_PORT> -A -n
```

---

## RHEL/CentOS/Rocky/AlmaLinux Manual Setup

These instructions apply to RHEL 7+, CentOS 7+, and other RHEL-based distributions.

### 1. Install Prerequisites

First, install the necessary packages using `yum` or `dnf`:

```bash
# For RHEL 7/CentOS 7
sudo yum install -y audit audispd-plugins rsyslog

# For RHEL 8+ and derivatives
sudo dnf install -y audit rsyslog
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

### 4. Configure SELinux

If SELinux is enabled on your system, you need to allow rsyslog to make network connections:

```bash
sudo setsebool -P rsyslog_can_network_connect on
```

### 5. Configure FirewallD

If FirewallD is enabled, you need to add a rule to allow traffic to the QRadar port:

```bash
sudo firewall-cmd --permanent --add-port=<QRADAR_PORT>/tcp
sudo firewall-cmd --reload
```

### 6. Configure Rsyslog Forwarding

Create a new rsyslog configuration file for QRadar:

```bash
sudo nano /etc/rsyslog.d/99-qradar.conf
```

Copy and paste the following configuration into the file, replacing `<QRADAR_IP>` and `<QRADAR_PORT>` with your QRadar server's IP address and port:

```
# QRadar Log Forwarding Configuration
template(name="QRadarFormat" type="string" string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name%: %msg%\\n")

if $syslogfacility-text == 'local3' then {
    action(
        type="omfwd"
        target="<QRADAR_IP>"
        port="<QRADAR_PORT>"
        protocol="tcp"
        template="QRadarFormat"
        queue.type="linkedlist"
        queue.size="50000"
        action.resumeRetryCount="-1"
    )
    stop
}
```

### 7. Restart Services

Restart the `auditd` and `rsyslog` services to apply the changes:

```bash
sudo systemctl restart auditd
sudo systemctl restart rsyslog
```

### 8. Verify the Setup

You can verify the setup by checking the logs on your QRadar server or by using `tcpdump` to monitor the traffic to your QRadar server:

```bash
sudo tcpdump -i any host <QRADAR_IP> and port <QRADAR_PORT> -A -n
```
