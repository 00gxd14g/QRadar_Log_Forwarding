# QRadar Unified Log Forwarding - V2 Edition

![QRadar](https://img.shields.io/badge/IBM-QRadar-blue?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![Linux](https://img.shields.io/badge/OS-Linux-yellow?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0.0-green?style=flat-square)

Advanced QRadar SIEM log forwarding solution with **MITRE ATT&CK framework integration**, dual forwarding methods, and comprehensive security monitoring designed for enterprise production environments.

## 🚀 V2 Edition Features

### 🎯 MITRE ATT&CK Integration
- **Comprehensive Technique Mapping**: Automatic detection and tagging of MITRE ATT&CK techniques
- **Enhanced Threat Detection**: Real-time analysis of commands and activities
- **Technique Coverage**: 50+ MITRE techniques including T1003, T1105, T1548, T1059, and more
- **Intelligent Parsing**: Advanced EXECVE argument processing with technique correlation

### 🔄 Dual Forwarding Methods
- **Audisp Method**: Traditional audisp-syslog plugin forwarding
- **Direct Method**: Direct audit log processing with systemd timers
- **Intelligent Fallback**: Automatic method selection based on system capabilities
- **Dual Mode**: Both methods for maximum reliability and coverage

### 🌍 Multi-Language Support
- **English Interface**: Default professional interface
- **Turkish Interface**: Native Turkish language support (`--lang=tr`)
- **Localized Messages**: Fully translated setup and error messages

### ⚙️ Advanced Configuration Options
- **Flexible Facility**: Support for local0-local7 syslog facilities (`--facility=local6`)
- **Method Selection**: Choose audisp, direct, or dual forwarding (`--method=dual`)
- **MITRE Mode**: Enable comprehensive MITRE integration (`--mitre-mode`)
- **Enhanced Security**: Non-eval command execution for improved security

## 📋 Quick Start

### Basic Installation
```bash
# Download V2 edition
git clone https://github.com/00gxd14g/QRadar_Log_Forwarding.git
cd QRadar_Log_Forwarding
chmod +x qradar_unified_v2.sh

# Basic setup
sudo ./qradar_unified_v2.sh 192.168.1.100 514
```

### Advanced Installation with MITRE
```bash
# Full MITRE ATT&CK integration with alternative facility
sudo ./qradar_unified_v2.sh 192.168.1.100 514 --mitre-mode --facility=local6

# Turkish interface with dual method
sudo ./qradar_unified_v2.sh 192.168.1.100 1514 --lang=tr --method=dual

# Direct method only (no audisp dependency)
sudo ./qradar_unified_v2.sh 192.168.1.100 514 --method=direct
```

## 🔧 Configuration Options

| Option | Description | Values | Default |
|--------|-------------|--------|---------|
| `--facility` | Syslog facility | local0-local7 | local3 |
| `--mitre-mode` | Enable MITRE ATT&CK | flag | disabled |
| `--lang` | Interface language | en, tr | en |
| `--method` | Forwarding method | audisp, direct, dual | dual |

## 🎯 MITRE ATT&CK Coverage

### Command and Control
- **T1059** - Command and Scripting Interpreter
- **T1105** - Ingress Tool Transfer
- **T1027** - Obfuscated Files or Information

### Privilege Escalation
- **T1548** - Abuse Elevation Control Mechanism
- **T1134** - Access Token Manipulation

### Credential Access
- **T1003** - OS Credential Dumping
- **T1552** - Unsecured Credentials

### Discovery
- **T1082** - System Information Discovery
- **T1087** - Account Discovery
- **T1005** - Data from Local System

### Persistence
- **T1053** - Scheduled Task/Job
- **T1543** - Create or Modify System Process

### Defense Evasion
- **T1070** - Indicator Removal on Host
- **T1036** - Masquerading

## 🔍 Enhanced Log Processing

### Traditional EXECVE Log
```
type=EXECVE msg=audit(1618834123.456:789): argc=3 a0="sudo" a1="-u" a2="root" a3="id"
```

### V2 MITRE-Enhanced Output
```
MITRE_PROCESSED: type=EXECVE msg=audit(1618834123.456:789): argc=3 cmd="sudo -u root id" mitre_techniques="T1548,T1134"
```

### Benefits
- **Technique Tagging**: Automatic MITRE technique identification
- **Command Reconstruction**: Complete command visibility
- **Threat Context**: Enhanced security intelligence
- **SIEM Integration**: Optimized for QRadar rule creation

## 🏗️ Architecture Overview

### Dual Method Architecture
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
            ┌───────▼───────┐   ┌───────▼────────┐
            │   rsyslog     │   │ systemd timer  │
            │   omprog      │   │ + rsyslog      │
            └───────────────┘   └────────────────┘
                    │                   │
                    └─────────┬─────────┘
                    ┌─────────▼─────────┐
                    │ MITRE ATT&CK      │
                    │ Parser            │
                    └───────────────────┘
```

## 📊 Performance Optimizations

### V2 Enhancements
- **Queue Management**: Advanced rsyslog queuing with disk buffering
- **Rate Limiting**: Intelligent rate limiting to prevent audit flooding
- **Noise Reduction**: Smart filtering to reduce unnecessary log volume
- **TCP Framing**: Proper octet-counted framing for reliable delivery
- **Memory Optimization**: Efficient memory usage for high-volume environments

### Configuration
```bash
# Buffer Size: 32768 (production optimized)
# Rate Limit: 200 events/second
# Queue Size: 100,000 messages
# Disk Buffer: 2GB maximum
# Batch Size: 1,000 messages
```

## 🔒 Security Features

### Enhanced Security Measures
- **Non-eval Execution**: Secure command execution without shell injection risks
- **Input Validation**: Comprehensive parameter validation
- **Signal Handling**: Graceful shutdown and cleanup
- **File Permissions**: Proper security context and permissions
- **Backup System**: Comprehensive configuration backup and recovery

### SELinux Integration
- **Context Management**: Automatic SELinux context configuration
- **Policy Compliance**: Compatible with enforcing SELinux policies
- **Boolean Configuration**: Automatic rsyslog network communication enablement

## 🧪 Testing and Validation

### Built-in Tests
```bash
# Test MITRE parser functionality
sudo python3 /usr/local/bin/qradar_mitre_parser.py --test

# Test local syslog
logger -p local6.info "V2 test message"

# Test audit events
sudo touch /etc/passwd

# Monitor QRadar traffic
sudo tcpdump -i any host 192.168.1.100 and port 514 -A
```

### Validation Results
- ✅ **Service Status**: Automatic service health checking
- ✅ **Configuration Syntax**: Rsyslog and audit rule validation
- ✅ **Network Connectivity**: QRadar reachability testing
- ✅ **MITRE Processing**: Technique detection validation
- ✅ **Log Generation**: End-to-end log flow verification

## 📁 File Locations

### V2 Specific Files
```
/etc/audit/rules.d/10-qradar-mitre.rules      # MITRE-enhanced audit rules
/etc/rsyslog.d/10-qradar-unified.conf         # Modern rsyslog configuration
/usr/local/bin/qradar_mitre_parser.py         # MITRE ATT&CK parser
/etc/systemd/system/qradar-audit-parser.*     # Systemd units for direct method
/var/log/qradar_unified_v2_setup.log          # V2 setup log
/etc/qradar_v2_backup_YYYYMMDD_HHMMSS/        # V2 configuration backups
```

## 🔄 Upgrade from V3.0.0

### Side-by-Side Installation
V2 Edition can run alongside the standard v3.0.0 installation:

```bash
# V2 uses different file paths and facility
# No conflicts with existing v3.0.0 installation
sudo ./qradar_unified_v2.sh 192.168.1.100 514 --facility=local6
```

### Migration Considerations
- **Different Facility**: V2 defaults to local3 but supports local6 to avoid conflicts
- **Enhanced Parser**: V2 includes MITRE technique mapping
- **Backup System**: V2 uses separate backup directories
- **Configuration Files**: V2 uses distinct file naming conventions

## 🛠️ Troubleshooting

### Common V2 Issues

#### MITRE Parser Issues
```bash
# Test parser directly
python3 /usr/local/bin/qradar_mitre_parser.py --test

# Check parser permissions
ls -la /usr/local/bin/qradar_mitre_parser.py

# Monitor parser errors
journalctl -u rsyslog -f | grep mitre
```

#### Systemd Timer Issues
```bash
# Check timer status
systemctl status qradar-audit-parser.timer

# Check service logs
journalctl -u qradar-audit-parser.service -f

# Restart timer
sudo systemctl restart qradar-audit-parser.timer
```

#### Facility Conflicts
```bash
# Check facility usage
netstat -tuln | grep 514
ss -tuln | grep 514

# Switch to alternative facility
sudo ./qradar_unified_v2.sh 192.168.1.100 514 --facility=local6
```

## 📈 Performance Monitoring

### Key Metrics
```bash
# Queue status
ls -la /var/spool/rsyslog/

# Processing statistics
grep "MITRE_PROCESSED" /var/log/syslog | wc -l

# Error rates
journalctl -u rsyslog --since "1 hour ago" | grep ERROR
```

## 🤝 Contributing to V2

V2 Edition welcomes contributions for:
- Additional MITRE technique mappings
- Enhanced parser logic
- Performance optimizations
- Language translations
- Platform compatibility improvements

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🆘 Support

- **V2 Issues**: [GitHub Issues](https://github.com/00gxd14g/QRadar_Log_Forwarding/issues) (tag with "v2-edition")
- **MITRE Questions**: Include MITRE technique details in issue description
- **Performance Issues**: Include system specifications and log volume data

---

**QRadar Unified V2 Edition - Advanced MITRE ATT&CK Integrated Security Monitoring** 🛡️

*Designed for enterprises requiring comprehensive threat detection and security intelligence*