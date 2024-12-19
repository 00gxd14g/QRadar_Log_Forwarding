# QRadar Log Forwarding Setup Script

![QRadar](https://www.ibm.com/design/language/assets/ibm_logo.svg)

## Overview

The **QRadar Log Forwarding Setup Script** is a comprehensive Bash script designed to automate the configuration of `auditd` and `rsyslog` on various Linux distributions to forward audit and system logs to IBM QRadar. The script not only sets up the necessary configurations but also includes diagnostic tools to detect and automatically fix common issues, ensuring seamless log transmission to your QRadar instance.

## Features

- **Multi-Distribution Support**: Compatible with Debian, Ubuntu, Red Hat, CentOS, and Oracle Linux.
- **Automated Package Installation**: Installs required packages (`auditd`, `audispd-plugins`, `rsyslog`) using the appropriate package manager.
- **Auditd Configuration**: Sets up audit rules to log all user commands and system activities.
- **Rsyslog Configuration**: Configures `rsyslog` to forward logs to QRadar using the `local1` facility.
- **Diagnostic and Auto-Fix**: Detects common configuration issues and attempts to automatically resolve them.
- **Comprehensive Logging**: Logs all script activities and diagnostic results to `/var/log/setup_logging.sh.log`.
- **Security Checks**: Verifies permissions and checks for SELinux/AppArmor settings that might interfere with log forwarding.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Script Functionality](#script-functionality)
- [Logging and Diagnostics](#logging-and-diagnostics)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Prerequisites

- **Supported Operating Systems**:
  - Debian (any version)
  - Ubuntu (any version)
  - Red Hat Enterprise Linux (RHEL) (any version)
  - CentOS (any version)
  - Oracle Linux (any version)
- **Root Privileges**: The script must be run with root permissions.
- **Network Access**: Ensure that the system can communicate with the QRadar server on the specified IP and port (default: TCP/514).

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/00gxd14g/qradar-log-forwarding.git
   cd qradar-log-forwarding```

## Usage

Run the script with the QRadar server IP address and port as arguments.

```bash
sudo bash /usr/local/bin/setup_logging.sh <QRADAR_IP> <QRADAR_PORT>
```
## Script Functionality

The `setup_logging.sh` script automates the configuration of `auditd` and `rsyslog` to forward logs to IBM QRadar. Below is a detailed breakdown of its functionality:

### Distribution and Version Detection

**Purpose**: Determines the Linux distribution and version to use the appropriate package manager.

**Supported Distributions:**

- Debian
- Ubuntu
- Red Hat Enterprise Linux (RHEL)
- CentOS
- Oracle Linux

### Package Installation

**Purpose**: Installs the necessary packages required for audit logging and syslog forwarding.

**Packages:**

- `auditd`: Provides a framework for auditing system events.
- `audispd-plugins`: Provides plugins for `auditd`.
- `rsyslog`: Provides the syslog daemon for forwarding logs.

**Process:**

- Uses `apt-get` for Debian/Ubuntu.
- Uses `dnf` or `yum` for Red Hat/CentOS/Oracle Linux.

### Service Configuration

#### Auditd Configuration

**Purpose**: Sets up audit rules to monitor system activities and user commands.

**Actions:**

- Creates or updates `/etc/audit/rules.d/audit.rules` with predefined audit rules.
- Ensures `auditd` is enabled and running.

#### Audisp-syslog Plugin Configuration

**Purpose**: Configures `auditd` to forward audit logs to `rsyslog`.

**Actions:**

- Configures `/etc/audit/plugins.d/syslog.conf` to enable the `audisp-syslog` plugin.
- Sets the plugin to use the `LOG_LOCAL1` facility.
- Restarts `auditd` to apply changes.

#### Rsyslog Configuration

**Purpose**: Configures `rsyslog` to forward logs to QRadar.

**Actions:**

- Creates or updates `/etc/rsyslog.d/60-qradar.conf` with forwarding rules for `local1.*` to the QRadar server.
- Restarts `rsyslog` to apply changes.

### Diagnostics and Auto-Fix

**Purpose**: Detects common configuration issues and attempts to automatically resolve them.

**Diagnostics:**

- **Rsyslog Diagnostics**: Checks if `rsyslog` is active, validates the configuration syntax, and ensures log files exist with correct permissions.
- **Auditd Diagnostics**: Checks if `auditd` is active, inspects audit logs for errors, and verifies that audit rules are correctly loaded.
- **Permissions Diagnostics**: Ensures `/var/log/syslog` has appropriate write permissions for `rsyslog`.
- **SELinux/AppArmor Diagnostics**: Checks if SELinux or AppArmor is enforcing policies that may block log forwarding.

**Auto-Fix Mechanisms:**

- If issues are detected in `rsyslog` or `auditd` configurations, the script attempts to fix the configurations and restart the services.

### Testing

#### Local Syslog Test

**Purpose**: Verifies that `rsyslog` is correctly forwarding logs locally.

**Actions:**

- Sends a test log message using the `logger` command.
- Checks if the message appears in `/var/log/syslog`.
- If not found, runs diagnostics and attempts to fix `rsyslog` configuration, then retries the test.

#### Audit Log Test

**Purpose**: Verifies that `auditd` is correctly logging system events and forwarding them to `rsyslog`.

**Actions:**

- Touches `/etc/passwd` to generate an audit event.
- Checks if the audit event appears using `ausearch`.
- Checks if the audit log is forwarded to `/var/log/syslog`.
- If not found, runs diagnostics and attempts to fix `auditd` and `audisp-syslog` configuration, then retries the test.

### Final Diagnostics

- **Permissions Check**: Ensures `/var/log/syslog` has the correct permissions.
- **SELinux/AppArmor Check**: Confirms that security modules are not blocking log forwarding.

### Logging

**Purpose**: Keeps a detailed log of all script actions and diagnostic results.

**Log File**: `/var/log/setup_logging.sh.log`

**Usage:**

- Review this log file to understand what actions the script performed and any issues it encountered or resolved.

### Final Instructions

**Network Verification**: The script suggests using `tcpdump` on the QRadar server to verify that logs are being received.

**Example Command:**

```bash
sudo tcpdump -i eth0 host <QRADAR_IP> and port <QRADAR_PORT> -nn -vv
```

---

This `Usage` and `Script Functionality` section is now formatted in Markdown and can be directly included in your `README.md` file on GitHub. Make sure to replace placeholders like `<QRADAR_IP>` and `<QRADAR_PORT>` with your actual QRadar server details when running the script.

### Additional Recommendations

- **Ensure Permissions**: Verify that the script has the necessary execute permissions and is run with root privileges.
  
- **Customize Audit Rules**: Depending on your specific logging requirements, you might want to customize the audit rules within the script.

- **Secure Log Transmission**: Consider configuring `rsyslog` to use TLS for secure log transmission to QRadar.

- **Regular Maintenance**: Regularly check the log file (`/var/log/setup_logging.sh.log`) for any issues or updates needed for your logging setup.

Feel free to modify the sections to better fit your project's specific needs or to add any additional information that might be helpful for users.


