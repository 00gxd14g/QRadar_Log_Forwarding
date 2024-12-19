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

---

This `Usage` and `Script Functionality` section is now formatted in Markdown and can be directly included in your `README.md` file on GitHub. Make sure to replace placeholders like `<QRADAR_IP>` and `<QRADAR_PORT>` with your actual QRadar server details when running the script.

### Additional Recommendations

- **Ensure Permissions**: Verify that the script has the necessary execute permissions and is run with root privileges.
  
- **Customize Audit Rules**: Depending on your specific logging requirements, you might want to customize the audit rules within the script.

- **Secure Log Transmission**: Consider configuring `rsyslog` to use TLS for secure log transmission to QRadar.

- **Regular Maintenance**: Regularly check the log file (`/var/log/setup_logging.sh.log`) for any issues or updates needed for your logging setup.

Feel free to modify the sections to better fit your project's specific needs or to add any additional information that might be helpful for users.


