# Changelog

All notable changes to the QRadar Log Forwarding project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-06-17

### Added - V2 Unified Edition
- **MITRE ATT&CK Framework Integration**: Comprehensive technique mapping and analysis
- **Dual Forwarding Methods**: Both audisp and direct audit log processing with intelligent fallback
- **Advanced MITRE Parser**: Enhanced Python script with technique detection and tagging
- **Multi-language Support**: English and Turkish interface (--lang=tr)
- **Flexible Facility Selection**: Support for local0-local7 facilities (--facility=local6)
- **Modern RainerScript**: Advanced rsyslog configuration with queue management and performance optimization
- **Enhanced Security**: Non-eval command execution and improved security practices
- **Comprehensive Firewall Management**: Automatic configuration for firewalld, UFW, and iptables
- **Advanced Error Handling**: Retry mechanisms and comprehensive fallback systems
- **Systemd Integration**: Native systemd timer support for direct audit processing
- **Production Optimizations**: Noise reduction, rate limiting, and performance tuning

### Enhanced Features
- **50+ MITRE-Mapped Audit Rules**: Comprehensive coverage of MITRE ATT&CK techniques
- **Queue Management**: Advanced rsyslog queuing with disk buffering and retry logic
- **Service Recovery**: Intelligent service management with multiple restart strategies
- **Comprehensive Testing**: Built-in validation for all components and connectivity
- **Enhanced Reporting**: Detailed setup summaries with troubleshooting information
- **Platform Detection**: Enhanced distribution detection using ID_LIKE for better compatibility

### Technical Improvements
- **Hex Decoding Support**: Handles hex-encoded audit arguments properly
- **Signal Handling**: Graceful shutdown and cleanup in Python parser
- **TCP Framing**: Proper octet-counted framing for reliable log delivery
- **Backup System**: Comprehensive configuration backup with timestamp tracking
- **File Tracking**: Complete audit trail of all file modifications

### Configuration Options
- `--mitre-mode`: Enable comprehensive MITRE ATT&CK integration
- `--method=dual|audisp|direct`: Choose forwarding method
- `--facility=local6`: Alternative syslog facility to avoid conflicts
- `--lang=tr`: Turkish language interface

### MITRE ATT&CK Coverage
- T1003 - OS Credential Dumping
- T1005 - Data from Local System  
- T1105 - Ingress Tool Transfer
- T1027 - Obfuscated Files or Information
- T1053 - Scheduled Task/Job
- T1059 - Command and Scripting Interpreter
- T1070 - Indicator Removal on Host
- T1082 - System Information Discovery
- T1134 - Access Token Manipulation
- T1548 - Abuse Elevation Control Mechanism
- And many more...

## [3.1.0] - 2025-06-18

### Added
- Enhanced audit rules loading with multiple fallback mechanisms
- Direct audit.log file monitoring as fallback when audit rules fail to load
- RHEL 7 audispd-plugins package auto-installation
- Line-by-line audit rule loading for problematic systems
- Comprehensive error handling for audit rule deployment
- Direct audit.log monitoring via rsyslog imfile module
- Enhanced diagnostics for direct audit monitoring

### Changed
- Script version updated to 3.1
- Improved RHEL 8 audit service management using `service` command instead of `systemctl`
- Enhanced audit rules validation with platform-specific handling
- Better error recovery for audit rules loading failures

### Fixed
- RHEL 7 audisp-syslog binary not found issue
- RHEL 8 auditd service management conflicts  
- RHEL 8 nested audit rules syntax errors
- Audit rules loading failures with automatic fallback to direct monitoring
- Enhanced compatibility across all supported RHEL versions

## [3.0.0] - 2025-06-17

### Added
- Complete rewrite of the setup script with unified functionality
- Universal Linux distribution support (Debian/Ubuntu/RHEL/CentOS/Oracle/AlmaLinux/Rocky)
- Comprehensive audit rules covering 50+ security monitoring points
- Enhanced Python concatenation script with proper error handling
- Automatic SELinux and firewall configuration for RHEL-based systems
- Built-in diagnostic and testing functions
- Configuration backup and recovery mechanisms
- Detailed logging with timestamped entries
- Network connectivity testing
- Command-line argument validation
- Proper file permissions and security considerations

### Changed
- Migrated from multiple script versions to single unified script
- Improved audit rule organization and categorization
- Enhanced rsyslog configuration with better error handling
- Updated Python script with robust argument processing
- Standardized file naming conventions and locations

### Fixed
- Language inconsistencies (removed Turkish comments)
- Configuration conflicts between different script versions
- Audit facility conflicts (standardized on local3)
- Path detection issues across different distributions
- Missing error handling in various functions
- Hardcoded values in configuration templates
- Python script argument ordering issues
- SELinux context and permission problems

### Removed
- Old script versions (setup_logging.sh, setup_logging-v2.sh, setup-loggingv2-rhel.sh)
- Duplicate configuration files
- Template files with placeholder values
- Unnecessary debugging output

### Security
- Enhanced file permission settings for all configuration files
- Proper SELinux context handling
- Firewall rule management for RHEL systems
- Input validation for IP addresses and port numbers
- Secure temporary file handling

## [2.0.0] - 2024-01-15

### Added
- Command concatenation functionality for EXECVE events
- RHEL-specific configuration support
- Basic error handling and logging
- Python script for argument processing

### Changed
- Improved audit rule structure
- Enhanced rsyslog configuration

### Fixed
- Binary path detection issues
- Service restart problems

## [1.0.0] - 2023-12-01

### Added
- Initial release
- Basic audit log forwarding to QRadar
- Support for Debian/Ubuntu systems
- Simple rsyslog configuration
- Basic audit rules

### Known Issues
- Limited distribution support
- No error handling
- Manual configuration required for some systems