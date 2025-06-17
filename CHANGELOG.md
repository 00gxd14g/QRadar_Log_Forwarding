# Changelog

All notable changes to the QRadar Log Forwarding project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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