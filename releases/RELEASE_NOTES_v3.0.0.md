# QRadar Log Forwarding v3.0.0 - Release Notes

## 🚀 Major Release: Complete Rewrite

This is a complete rewrite of the QRadar Log Forwarding solution, providing enterprise-grade functionality for production environments.

## ✨ What's New

### 🌐 Universal Linux Support
- **Multi-Distribution**: Works on Debian, Ubuntu, Kali, RHEL, CentOS, Oracle Linux, AlmaLinux, and Rocky Linux
- **Automatic Detection**: Intelligently detects distribution and adapts configuration accordingly
- **Version Compatibility**: Supports all current and LTS versions

### 🛡️ Enhanced Security Monitoring
- **50+ Audit Rules**: Comprehensive security monitoring covering all critical system areas
- **Categorized Monitoring**: Identity changes, privilege escalation, network modifications, suspicious activities
- **Immutable Rules**: Audit rules are protected against tampering with `-e 2` flag

### 🔧 Advanced Features
- **Command Concatenation**: EXECVE arguments are automatically concatenated for better SIEM parsing
- **Intelligent Error Handling**: Robust error recovery and diagnostic capabilities
- **Configuration Backup**: Automatic backup of existing configurations before modification
- **File Tracking**: Complete visibility into all modified files during setup

### 🏢 Production Ready
- **SELinux Integration**: Automatic SELinux configuration for RHEL-based systems
- **Firewall Management**: Automatic firewall rule configuration
- **Network Testing**: Built-in connectivity testing to QRadar
- **Comprehensive Logging**: Detailed setup logs with timestamps

## 📊 Configuration Overview

### Audit Monitoring Categories
- **System Administration**: Password files, sudo config, SSH settings
- **Command Execution**: All root commands and privileged user activities
- **Network Configuration**: Hostname changes, interface configs, DNS settings
- **Security Events**: Privilege escalation attempts, suspicious tool usage
- **System State**: Kernel modules, system shutdown/reboot events

### File Locations
```
/etc/audit/rules.d/qradar.rules          # 50+ audit rules
/etc/audit/plugins.d/syslog.conf         # Audit dispatcher config
/etc/rsyslog.d/10-qradar.conf            # QRadar forwarding rules
/usr/local/bin/concat_execve.py          # Command concatenation script
/var/log/qradar_setup.log                # Setup execution log
/etc/qradar_backup_YYYYMMDD_HHMMSS/      # Configuration backups
```

## 🔧 Installation

### Quick Start
```bash
# Download and setup
git clone https://github.com/00gxd14g/QRadar_Log_Forwarding.git
cd QRadar_Log_Forwarding
chmod +x setup_qradar_logging.sh

# Run installation
sudo ./setup_qradar_logging.sh <QRADAR_IP> <QRADAR_PORT>
```

### Example
```bash
sudo ./setup_qradar_logging.sh 192.168.1.100 514
```

## ✅ Testing & Verification

The script includes comprehensive testing:

### Automatic Tests
- Service status verification
- Configuration syntax validation
- Network connectivity testing
- Audit functionality testing

### Manual Testing
```bash
# Test local syslog
logger -p local3.info "Test message to QRadar"

# Test audit events
sudo touch /etc/passwd

# Monitor network traffic
sudo tcpdump -i any host <QRADAR_IP> and port <QRADAR_PORT> -A -n

# Test command concatenation
python3 /usr/local/bin/concat_execve.py --test
```

## 🔍 Log Processing

### EXECVE Processing
**Before:**
```
type=EXECVE msg=audit(1618834123.456:789): argc=3 a0="ls" a1="-la" a2="/tmp"
```

**After:**
```
PROCESSED: type=EXECVE msg=audit(1618834123.456:789): argc=3 cmd="ls -la /tmp"
```

## 🛠️ Troubleshooting

### Service Issues
```bash
sudo systemctl status auditd rsyslog
sudo journalctl -u auditd -f
```

### Network Issues
```bash
sudo telnet <QRADAR_IP> <QRADAR_PORT>
sudo tcpdump -i any host <QRADAR_IP>
```

### Configuration Issues
```bash
sudo python3 /usr/local/bin/concat_execve.py --test
sudo augenrules --load
```

## 📋 Breaking Changes

### Removed Features
- Old script versions (`setup_logging.sh`, `setup_logging-v2.sh`)
- Template configuration files with placeholders
- Language inconsistencies (Turkish comments removed)

### Migration Path
This version completely replaces previous versions. No migration is needed - simply run the new script on a fresh system or after backing up existing configurations.

## 🔒 Security Considerations

### File Permissions
- Audit rules: `640` (root:root)
- Plugin configs: `640` (root:root)  
- Python script: `755` (executable)
- Log files: `640` (root:root)

### SELinux
- Automatic `rsyslogd_can_network_connect` boolean enabling
- Proper context restoration for Python script
- SELinux status logging

### Firewall
- Automatic QRadar port addition to firewalld
- Permanent rule configuration
- Rule verification

## 📈 Performance

### Optimizations
- Audit buffer size: 16384 (production optimized)
- Rsyslog queue size: 50,000 messages
- Intelligent log filtering to reduce noise
- Efficient argument concatenation

### Resource Usage
- Minimal CPU overhead
- Low memory footprint
- Optimized for high-volume audit environments

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/00gxd14g/QRadar_Log_Forwarding/issues)
- **Documentation**: [Project Wiki](https://github.com/00gxd14g/QRadar_Log_Forwarding/wiki)

---

**Download:** [QRadar_Log_Forwarding_v3.0.0.tar.gz](https://github.com/00gxd14g/QRadar_Log_Forwarding/archive/refs/tags/v3.0.0.tar.gz)

**SHA256:** `f970fbf0243f342e34cbfe5fa2e2eed1be6d44cb7d5b3d442e826ae9fdb8632c`

---

*Made with ❤️ for better security monitoring*