# QRadar Unified V2 Edition v2.0.0 - Release Notes

## 🚀 Major Release: MITRE ATT&CK Integrated Edition

This is the **V2 Unified Edition** featuring comprehensive **MITRE ATT&CK framework integration**, dual forwarding methods, and advanced security monitoring capabilities for enterprise environments.

## ✨ What's New in V2 Edition

### 🎯 MITRE ATT&CK Framework Integration
- **Comprehensive Technique Mapping**: Automatic detection and tagging of 50+ MITRE ATT&CK techniques
- **Real-time Analysis**: Advanced EXECVE command processing with technique correlation
- **Enhanced Threat Detection**: Intelligent parsing with security context awareness
- **Technique Coverage**: T1003, T1105, T1548, T1059, T1070, T1082, T1134, and many more

### 🔄 Dual Forwarding Architecture
- **Audisp Method**: Traditional audisp-syslog plugin forwarding
- **Direct Method**: Direct audit log processing with systemd timers
- **Intelligent Fallback**: Automatic method selection based on system capabilities
- **Dual Mode**: Both methods simultaneously for maximum reliability

### 🌍 Multi-Language Support
- **English Interface**: Professional default interface
- **Turkish Interface**: Complete Turkish localization (`--lang=tr`)
- **Localized Messages**: Fully translated setup, error, and status messages

### ⚙️ Advanced Configuration Options
- **Flexible Facility Selection**: Support for local0-local7 syslog facilities
- **Method Selection**: Choose audisp, direct, or dual forwarding methods
- **MITRE Mode Toggle**: Enable/disable comprehensive MITRE integration
- **Enhanced Security**: Non-eval command execution for improved security posture

## 🔧 Installation & Usage

### Quick Start
```bash
# Basic installation
sudo ./qradar_unified_v2.sh 192.168.1.100 514

# Advanced MITRE integration
sudo ./qradar_unified_v2.sh 192.168.1.100 514 --mitre-mode --facility=local6

# Turkish interface with dual method
sudo ./qradar_unified_v2.sh 192.168.1.100 1514 --lang=tr --method=dual
```

### Configuration Options
| Option | Description | Values | Default |
|--------|-------------|--------|---------|
| `--facility` | Syslog facility | local0-local7 | local3 |
| `--mitre-mode` | Enable MITRE ATT&CK | flag | disabled |
| `--lang` | Interface language | en, tr | en |
| `--method` | Forwarding method | audisp, direct, dual | dual |

## 🏗️ Technical Architecture

### Enhanced Components
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Audit Events  │───▶│  Method Selection │───▶│   QRadar SIEM   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
            ┌───────▼───────┐   ┌───────▼────────┐
            │  Audisp Method │   │  Direct Method │
            └───────────────┘   └────────────────┘
                    │                   │
                    └─────────┬─────────┘
                    ┌─────────▼─────────┐
                    │ MITRE ATT&CK      │
                    │ Enhanced Parser   │
                    └───────────────────┘
```

## 🎯 MITRE ATT&CK Coverage

### Comprehensive Technique Detection
- **T1003** - OS Credential Dumping (passwd, shadow, group files)
- **T1005** - Data from Local System (find, locate, grep commands)
- **T1105** - Ingress Tool Transfer (wget, curl, nc, scp)
- **T1027** - Obfuscated Files or Information (base64, xxd, openssl)
- **T1053** - Scheduled Task/Job (crontab, systemctl, service)
- **T1059** - Command and Scripting Interpreter (bash, python, perl)
- **T1070** - Indicator Removal on Host (rm, shred, history clearing)
- **T1082** - System Information Discovery (uname, whoami, ps)
- **T1134** - Access Token Manipulation (sudo, su, runuser)
- **T1548** - Abuse Elevation Control Mechanism (sudo, pkexec, setuid)

### Enhanced Log Processing
**Traditional EXECVE Log:**
```
type=EXECVE msg=audit(1618834123.456:789): argc=3 a0="sudo" a1="-u" a2="root" a3="id"
```

**V2 MITRE-Enhanced Output:**
```
MITRE_PROCESSED: type=EXECVE msg=audit(1618834123.456:789): argc=3 cmd="sudo -u root id" mitre_techniques="T1548,T1134"
```

## 🚀 Performance Enhancements

### Advanced Queue Management
- **Buffer Size**: 32768 (production optimized for high-volume)
- **Rate Limiting**: 200 events/second to prevent audit flooding
- **Queue Management**: 100,000 message queue with 2GB disk buffering
- **Batch Processing**: 1,000 message batches for efficient forwarding
- **TCP Framing**: Proper octet-counted framing for reliable delivery

### Modern RainerScript Configuration
```bash
# Advanced rsyslog configuration with queue management
main_queue(
  queue.type="linkedlist"
  queue.filename="qradar_main_queue"
  queue.maxdiskspace="2g"
  queue.saveonshutdown="on"
)
```

## 🔒 Security Features

### Enhanced Security Measures
- **Non-eval Command Execution**: Secure command execution without shell injection risks
- **Input Validation**: Comprehensive parameter and IP address validation
- **Signal Handling**: Graceful shutdown and cleanup in Python parser
- **File Permissions**: Proper security contexts and restricted permissions
- **Backup System**: Comprehensive configuration backup with recovery capabilities

### Multi-Platform Firewall Support
- **firewalld**: Automatic configuration for RHEL/CentOS systems
- **UFW**: Native Ubuntu firewall integration
- **iptables**: Fallback support for legacy systems
- **Automatic Detection**: Intelligent firewall system detection and configuration

## 📁 V2 File Locations

### Enhanced File Structure
```
/etc/audit/rules.d/10-qradar-mitre.rules      # 50+ MITRE-mapped audit rules
/etc/rsyslog.d/10-qradar-unified.conf         # Modern queue-managed rsyslog config
/usr/local/bin/qradar_mitre_parser.py         # MITRE ATT&CK enhanced parser
/etc/systemd/system/qradar-audit-parser.*     # Systemd units for direct method
/var/log/qradar_unified_v2_setup.log          # V2 comprehensive setup log
/etc/qradar_v2_backup_YYYYMMDD_HHMMSS/        # V2 timestamped backups
```

## 🧪 Comprehensive Testing

### Built-in Validation Suite
```bash
# Test MITRE parser functionality
python3 /usr/local/bin/qradar_mitre_parser.py --test

# Test syslog forwarding
logger -p local6.info "V2 test message"

# Test audit event generation
sudo touch /etc/passwd

# Monitor QRadar network traffic
sudo tcpdump -i any host 192.168.1.100 and port 514 -A
```

### Validation Coverage
- ✅ **Service Health**: Automatic service status monitoring
- ✅ **Configuration Syntax**: Rsyslog and audit rule validation
- ✅ **Network Connectivity**: QRadar reachability and port testing
- ✅ **MITRE Processing**: Technique detection and tagging validation
- ✅ **End-to-End Flow**: Complete log flow verification

## 🔄 Compatibility & Migration

### V3.0.0 Compatibility
- **Side-by-Side Installation**: V2 can run alongside existing v3.0.0
- **Different Facilities**: V2 supports local6 to avoid conflicts
- **Separate Backups**: V2 uses distinct backup directories
- **Independent Configuration**: No conflicts with existing setups

### Migration Considerations
- **Facility Selection**: Use `--facility=local6` to avoid conflicts
- **Enhanced Features**: V2 includes MITRE mapping not in v3.0.0
- **Method Flexibility**: Choose dual, audisp, or direct based on requirements
- **Language Support**: Turkish interface available for international deployments

## 🛠️ Troubleshooting

### V2 Specific Issues

#### MITRE Parser Troubleshooting
```bash
# Test parser directly
python3 /usr/local/bin/qradar_mitre_parser.py --test

# Check parser logs
journalctl -u rsyslog -f | grep MITRE

# Verify parser permissions
ls -la /usr/local/bin/qradar_mitre_parser.py
```

#### Systemd Timer Issues
```bash
# Check timer status
systemctl status qradar-audit-parser.timer

# Monitor service logs
journalctl -u qradar-audit-parser.service -f

# Restart components
sudo systemctl restart qradar-audit-parser.timer
```

## 📊 Monitoring & Performance

### Key Performance Metrics
```bash
# Queue monitoring
ls -la /var/spool/rsyslog/qradar_*

# MITRE processing statistics
grep "MITRE_PROCESSED" /var/log/syslog | wc -l

# Error rate monitoring
journalctl -u rsyslog --since "1 hour ago" | grep ERROR | wc -l
```

## 🔍 Advanced Features

### Intelligent Method Selection
- **Audisp Availability Detection**: Automatic detection of audisp-syslog capability
- **Fallback Mechanisms**: Graceful degradation when components unavailable
- **Dual Method Benefits**: Redundancy and comprehensive coverage
- **Performance Optimization**: Method selection based on system capabilities

### Enhanced Error Handling
- **Retry Logic**: Comprehensive retry mechanisms for critical operations
- **Service Recovery**: Intelligent service restart and recovery procedures
- **Graceful Degradation**: Continued operation despite component failures
- **Comprehensive Logging**: Detailed error reporting and troubleshooting information

## 📋 System Requirements

### Supported Distributions
- **Debian Family**: Debian 9+, Ubuntu 18.04+, Kali Linux
- **RHEL Family**: RHEL 7+, CentOS 7+, Oracle Linux 7+, AlmaLinux 8+, Rocky Linux 8+
- **Enhanced Detection**: Uses ID_LIKE for improved distribution family detection

### Resource Requirements
- **CPU**: Minimal overhead, optimized for production
- **Memory**: Efficient memory usage with queue management
- **Disk**: 2GB queue buffering capacity
- **Network**: TCP connectivity to QRadar on specified port

## 🎉 What's Next

### Future V2 Enhancements
- Additional MITRE technique mappings
- Enhanced parser performance optimizations
- Extended language support
- Advanced threat correlation capabilities
- Machine learning integration for anomaly detection

## 📝 License & Support

**License**: MIT License - see [LICENSE](LICENSE) file for details

**Support Channels**:
- **GitHub Issues**: [V2 Edition Issues](https://github.com/00gxd14g/QRadar_Log_Forwarding/issues) (tag with "v2-edition")
- **MITRE Questions**: Include technique details and use case scenarios
- **Performance Issues**: Provide system specifications and log volume data

---

**Download**: [QRadar_Unified_V2_v2.0.0.tar.gz](https://github.com/00gxd14g/QRadar_Log_Forwarding/releases/download/v2.0.0/QRadar_Unified_V2_v2.0.0.tar.gz)

**SHA256**: `8882857625a285eb41b5384c5ce1012b0604062a4e14cf84f5d136efc1b28028`

---

*QRadar Unified V2 Edition - Advanced MITRE ATT&CK Integrated Security Monitoring* 🛡️

*Designed for enterprises requiring comprehensive threat detection and security intelligence*