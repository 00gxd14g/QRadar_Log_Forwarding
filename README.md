# QRadar Log Forwarding Setup

![QRadar](https://img.shields.io/badge/IBM-QRadar-blue?style=flat-square)
![Linux](https://img.shields.io/badge/OS-Linux-yellow?style=flat-square)
![Bash](https://img.shields.io/badge/Shell-Bash-green?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.6+-red?style=flat-square)
![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-orange?style=flat-square)
![Docker](https://img.shields.io/badge/Tests-Docker-blue?style=flat-square)
![Build Status](https://img.shields.io/github/actions/workflow/status/your-org/QRadar_Log_Forwarding/ci.yml?branch=main&style=flat-square)

An enterprise-grade, production-ready solution for configuring Linux systems to forward audit logs to IBM QRadar SIEM.

## 🚀 Features

- **Universal Linux Support**: Compatible with Debian/Ubuntu, RHEL/CentOS, Oracle Linux, AlmaLinux, and Rocky Linux
- **Intelligent Distribution Detection**: Automatically detects and adapts to different Linux distributions and versions
- **Advanced Log Filtering**: Filters out noisy and irrelevant logs to reduce QRadar EPS.
- **Rich JSON Log Format**: Enriches logs with additional metadata and formats them as JSON for easy parsing in QRadar.
- **Command Concatenation**: Advanced Python script that concatenates EXECVE command arguments for better SIEM parsing
- **RHEL Compatibility**: Enhanced RHEL 7/8/9 support with platform-specific service management
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

   # Option 2: Download latest release
   wget https://github.com/00gxd14g/QRadar_Log_Forwarding/releases/latest/download/qradar_universal_installer.sh
   chmod +x qradar_universal_installer.sh
   ```

2. **Run the universal installer**:
   ```bash
   sudo ./src/installers/universal/qradar_universal_installer.sh <QRADAR_IP> <QRADAR_PORT>
   ```

### Example Usage

```bash
# Configure for QRadar at 192.168.1.100 on port 514
sudo ./src/installers/universal/qradar_universal_installer.sh 192.168.1.100 514
```

### Command Line Arguments

| Parameter | Description | Example |
|-----------|-------------|---------|
| `QRADAR_IP` | IP address of your QRadar server | `192.168.1.100` |
| `QRADAR_PORT` | Port number for log forwarding | `514` |
| `--minimal` | Use minimal audit rules for low EPS | Optional |
| `--dry-run` | Test mode without system modifications | Optional |

## 🧪 Testing

### Automated CI/CD
This project includes comprehensive automated testing via GitHub Actions:

- **Syntax Validation**: All shell scripts and Python code
- **Docker Integration Tests**: Multi-platform installer testing
- **Configuration Validation**: Rsyslog and audit rule verification
- **Artifact Generation**: Automated release preparation

### Manual Testing
```bash
# Run all Docker tests
cd tests/docker
./run_tests.sh

# Test specific platform
docker build -f tests/docker/Dockerfile.ubuntu -t qradar-ubuntu-test .
docker run --rm qradar-ubuntu-test

# Syntax check
find . -name "*.sh" -type f | xargs shellcheck
```

### Test Coverage
- ✅ Ubuntu 24.04 installer
- ✅ Debian 12 installer  
- ✅ RHEL/Rocky Linux 9 installer
- ✅ Universal installer
- ✅ Python parser scripts
- ✅ Configuration file validation

## 🔧 For more details, see the [documentation](docs/README.md).
