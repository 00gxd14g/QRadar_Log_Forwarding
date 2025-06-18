# QRadar Log Forwarding Setup

![QRadar](https://img.shields.io/badge/IBM-QRadar-blue?style=flat-square)
![Linux](https://img.shields.io/badge/OS-Linux-yellow?style=flat-square)
![Bash](https://img.shields.io/badge/Shell-Bash-green?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.6+-red?style=flat-square)

An enterprise-grade, production-ready solution for configuring Linux systems to forward audit logs to IBM QRadar SIEM with optimized log filtering, command argument concatenation, and comprehensive security monitoring designed for customer environments.

## 🚀 Features

- **Universal Linux Support**: Compatible with Debian/Ubuntu, RHEL/CentOS, Oracle Linux, AlmaLinux, and Rocky Linux
- **Intelligent Distribution Detection**: Automatically detects and adapts to different Linux distributions and versions
- **Enhanced Audit Rules Management**: Multi-layered audit rules loading with intelligent fallback mechanisms
- **Direct Audit.Log Monitoring**: Automatic fallback to direct /var/log/audit/audit.log monitoring when audit rules fail
- **Command Concatenation**: Advanced Python script that concatenates EXECVE command arguments for better SIEM parsing
- **RHEL Compatibility**: Enhanced RHEL 7/8 support with platform-specific service management
- **SELinux & Firewall Integration**: Automatic configuration for RHEL-based systems
- **Robust Error Handling**: Comprehensive logging, backup creation, and diagnostic functions
- **Production Ready**: Designed for enterprise environments with proper error handling and recovery

## 📋 Prerequisites

### System Requirements
- **Root Access**: Must be run with sudo/root privileges
- **Supported Operating Systems**:
  - Debian (9, 10, 11, 12)
  - Ubuntu (18.04, 20.04, 22.04, 24.04)
  - Kali Linux (current)
  - RHEL/CentOS (7, 8, 9)
  - Oracle Linux (7, 8, 9)
  - AlmaLinux (8, 9)
  - Rocky Linux (8, 9)

### Network Requirements
- **QRadar Connectivity**: System must be able to reach QRadar server on specified IP and port
- **Default Port**: TCP 514 (syslog), but configurable
- **Firewall**: Script automatically configures firewalld on RHEL-based systems

### Package Dependencies
The script automatically installs required packages:
- `auditd` - Linux audit framework
- `audispd-plugins` - Audit dispatcher plugins (Debian/Ubuntu)
- `rsyslog` - System logging daemon
- `python3` - Required for command concatenation script

## 🛠️ Installation & Usage

### Quick Start

1. **Download the latest release**:
   ```bash
   # Option 1: Clone the repository
   git clone https://github.com/00gxd14g/QRadar_Log_Forwarding.git
   cd QRadar_Log_Forwarding
   chmod +x setup_qradar_logging.sh
   
   # Option 2: Download latest release
   wget https://github.com/00gxd14g/QRadar_Log_Forwarding/releases/latest/download/setup_qradar_logging.sh
   chmod +x setup_qradar_logging.sh
   ```

2. **Run the enhanced setup**:
   ```bash
   sudo ./setup_qradar_logging.sh <QRADAR_IP> <QRADAR_PORT>
   ```

### Example Usage

```bash
# Configure for QRadar at 192.168.1.100 on port 514
sudo ./setup_qradar_logging.sh 192.168.1.100 514

# Configure for QRadar at 10.0.0.50 on port 1514
sudo ./setup_qradar_logging.sh 10.0.0.50 1514
```

### Command Line Arguments

| Parameter | Description | Example |
|-----------|-------------|---------|
| `QRADAR_IP` | IP address of your QRadar server | `192.168.1.100` |
| `QRADAR_PORT` | Port number for log forwarding | `514` |

## 🔧 Configuration Details

### Audit Rules Coverage

The script implements comprehensive security monitoring covering:

#### System Administration
- Password file modifications (`/etc/passwd`, `/etc/shadow`)
- User and group management (`/etc/group`, `/etc/gshadow`)
- Sudo configuration changes (`/etc/sudoers`)
- SSH configuration monitoring

#### Command Execution
- All root commands (`euid=0`)
- User commands (`euid>=1000`)
- Privilege escalation attempts (`su`, `sudo`)
- Shell and interpreter execution

#### Network Configuration
- Hostname and domain changes
- Network interface configuration
- Hosts file modifications
- Distribution-specific network scripts

#### System State Changes
- System shutdown/reboot commands
- Kernel module loading/unloading
- Authentication system changes (PAM)

#### Suspicious Activities
- Network tools usage (`wget`, `curl`, `nc`)
- Remote access tools (`ssh`, `scp`, `rsync`)
- Temporary file system access
- System call monitoring (`ptrace`)

### File Locations

After installation, configuration files are located at:

```
/etc/audit/rules.d/qradar.rules          # Audit rules
/etc/audit/plugins.d/syslog.conf         # Audisp-syslog plugin config
/etc/rsyslog.d/10-qradar.conf            # Rsyslog QRadar forwarding config
/usr/local/bin/concat_execve.py          # Command concatenation script
/var/log/qradar_setup.log                # Installation log
/etc/qradar_backup_YYYYMMDD_HHMMSS/      # Configuration backups
```

## 🔍 Testing & Verification

### Automated Testing

The script includes built-in diagnostic functions that test:

1. **Service Status**: Verifies auditd and rsyslog are running
2. **Configuration Validation**: Checks rsyslog configuration syntax
3. **Local Syslog Test**: Sends test message through syslog pipeline
4. **Audit Functionality**: Triggers audit event and verifies logging
5. **Network Connectivity**: Tests connection to QRadar server

### Manual Testing

#### Test Local Syslog
```bash
logger -p local3.info "Test message to QRadar"
```

#### Test Audit Events
```bash
sudo touch /etc/passwd  # Triggers identity_changes audit rule
```

#### Monitor Network Traffic
```bash
sudo tcpdump -i any host <QRADAR_IP> and port <QRADAR_PORT> -A -n
```

#### Check Command Concatenation
```bash
# Test the Python script directly
echo 'type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="ls" a1="-la" a2="/tmp"' | python3 /usr/local/bin/concat_execve.py --test
```

## 🛡️ Security Considerations

### SELinux Configuration
For RHEL-based systems with SELinux enabled, the script automatically:
- Enables `rsyslogd_can_network_connect` boolean
- Restores proper SELinux contexts for the Python script
- Logs SELinux-related warnings for manual review

### Firewall Configuration
On systems with firewalld active, the script:
- Adds the QRadar port to the firewall rules
- Applies changes permanently
- Verifies rule activation

### File Permissions
All configuration files are created with appropriate permissions:
- Audit rules: `640` (root:root)
- Plugin configurations: `640` (root:root)
- Python script: `755` (executable)
- Log files: `640` (root:root)

## 🔄 Enhanced Reliability Features (v3.1+)

### Multi-Layered Audit Rules Loading
The script now uses multiple approaches to ensure audit rules are loaded:

1. **Primary Method**: Platform-specific audit rules loading (augenrules/auditctl)
2. **Fallback Method**: Line-by-line rule loading for problematic systems
3. **Ultimate Fallback**: Direct audit.log file monitoring via rsyslog

### Direct Audit.Log Monitoring
When traditional audit rules fail to load, the script automatically configures:
- **imfile module**: Direct monitoring of `/var/log/audit/audit.log`
- **Automatic Processing**: EXECVE concatenation works in both modes
- **Seamless Fallback**: No manual intervention required
- **Full Functionality**: All audit events are still forwarded to QRadar

### RHEL-Specific Enhancements
- **RHEL 7**: Automatic audispd-plugins package installation
- **RHEL 8**: Enhanced service management using service commands
- **Platform Detection**: Intelligent handling of distribution-specific quirks
- **Error Recovery**: Comprehensive retry mechanisms

## 📊 Log Format & Processing

### Original EXECVE Format
```
type=EXECVE msg=audit(1618834123.456:789): argc=3 a0="ls" a1="-la" a2="/tmp"
```

### Processed Format
```
QRADAR_PROCESSED: type=EXECVE msg=audit(1618834123.456:789): argc=3 cmd="ls -la /tmp"
```

### Benefits
- **Simplified Parsing**: Single `cmd` field instead of multiple `aX` fields
- **Better Readability**: Complete command visible in SIEM
- **Enhanced Analytics**: Easier to create QRadar rules and searches
- **Processing Indicator**: `QRADAR_PROCESSED` prefix for tracking

## 🆘 Troubleshooting Guide

For comprehensive troubleshooting, see **[MANUAL_FIXES.md](MANUAL_FIXES.md)** which includes:
- Platform-specific manual fix procedures
- RHEL 7/8 specific issues and solutions
- Service management commands
- Network connectivity tests
- Step-by-step recovery procedures

### Common Issues

#### Services Not Starting
```bash
# Check service status
sudo systemctl status auditd rsyslog

# Check logs
sudo journalctl -u auditd -f
sudo journalctl -u rsyslog -f
```

#### No Logs Reaching QRadar
```bash
# Verify local syslog is working
sudo grep "local3" /var/log/syslog

# Check network connectivity
sudo telnet <QRADAR_IP> <QRADAR_PORT>

# Monitor outbound traffic
sudo tcpdump -i any host <QRADAR_IP> and port <QRADAR_PORT>
```

#### SELinux Denials
```bash
# Check for AVC denials
sudo ausearch -m avc -ts recent

# Check SELinux booleans
sudo getsebool -a | grep rsyslog
```

#### Python Script Issues
```bash
# Test script manually
sudo python3 /usr/local/bin/concat_execve.py --test

# Check script permissions
ls -la /usr/local/bin/concat_execve.py
```

### Log Files

Check these log files for troubleshooting:
- `/var/log/qradar_setup.log` - Setup script execution log
- `/var/log/audit/audit.log` - Audit events
- `/var/log/syslog` or `/var/log/messages` - System logs
- `/var/log/omprog_execve_output.log` - Python script output (if configured)

## 🔄 Maintenance

### Regular Tasks

#### Update Audit Rules
Edit `/etc/audit/rules.d/qradar.rules` and reload:
```bash
sudo augenrules --load
sudo systemctl restart auditd
```

#### Monitor Log Volume
```bash
# Check audit log size
sudo du -sh /var/log/audit/

# Monitor syslog rates
sudo journalctl -u rsyslog --since "1 hour ago" | wc -l
```

#### Verify QRadar Connectivity
```bash
# Test connection periodically
timeout 5 bash -c "cat < /dev/null > /dev/tcp/<QRADAR_IP>/<QRADAR_PORT>"
```

### Configuration Backup

The script automatically creates backups in:
```
/etc/qradar_backup_YYYYMMDD_HHMMSS/
```

To restore from backup:
```bash
sudo cp /etc/qradar_backup_*/filename /etc/original/location/
sudo systemctl restart auditd rsyslog
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Add tests for new functionality
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature/improvement`)
7. Create a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support & Documentation

- **Issues**: Report bugs and feature requests on [GitHub Issues](https://github.com/00gxd14g/QRadar_Log_Forwarding/issues)
- **Releases**: Download latest versions from [GitHub Releases](https://github.com/00gxd14g/QRadar_Log_Forwarding/releases)
- **Troubleshooting**: See [MANUAL_FIXES.md](MANUAL_FIXES.md) for comprehensive troubleshooting
- **Changelog**: View [CHANGELOG.md](CHANGELOG.md) for detailed version history
- **Security**: Report security vulnerabilities privately to the project maintainer

## 📈 Latest Updates

### Version 3.1.0 (Current) ✨
- **Enhanced Audit Rules Management**: Multi-layered loading with intelligent fallbacks
- **Direct Audit.Log Monitoring**: Automatic fallback when audit rules fail
- **RHEL 7/8 Compatibility**: Platform-specific fixes and enhancements
- **Line-by-Line Rule Loading**: For problematic systems
- **Comprehensive Error Recovery**: Automatic fallback mechanisms
- **Enhanced Documentation**: Complete troubleshooting guide

### Version 3.0.0
- Complete rewrite with unified script
- Enhanced error handling and logging
- Comprehensive audit rules (50+ monitoring points)
- Improved Python concatenation script
- Automatic SELinux and firewall configuration
- Support for all major Linux distributions
- Built-in diagnostic and testing functions

### Version 2.0.0
- Added command concatenation functionality
- Improved RHEL support
- Basic error handling

### Version 1.0.0
- Initial release
- Basic audit forwarding
- Limited distribution support

**Full Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

**Made with ❤️ for better security monitoring**