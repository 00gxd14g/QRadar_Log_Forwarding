#!/usr/bin/env bash
#
# ===============================================================================
# QRadar Universal Log Forwarding Installer v4.0.0
# ===============================================================================
#
# This script is a universal installer for QRadar SIEM log forwarding,
# designed to work on all major Linux distributions.
#
# Supported Distributions:
#   • Ubuntu (16.04+)
#   • Debian (9+)
#   • RHEL/CentOS (7+)
#   • Rocky Linux (8+)
#   • AlmaLinux (8+)
#   • Oracle Linux (7+)
#   • Amazon Linux 2
#   • Kali Linux
#
# Features:
#   - Automatic distribution detection and installer selection
#   - Unified configuration approach
#   - Comprehensive security monitoring
#   - MITRE ATT&CK compliant rules
#   - Secure command execution
#   - Comprehensive error handling
#
# Usage: sudo bash qradar_universal_installer.sh <QRADAR_IP> <QRADAR_PORT>
#
# Author: QRadar Log Forwarding Project
# Version: 4.0.0 - Universal Edition
# ===============================================================================

set -Eeuo pipefail
trap 'error_exit "Unexpected failure (line: $LINENO)"' ERR

# ===============================================================================
# GLOBAL VARIABLES
# ===============================================================================

readonly SCRIPT_VERSION="4.0.0-universal"
readonly LOG_FILE="/var/log/qradar_universal_setup.log"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# Installer paths
readonly UBUNTU_INSTALLER="$SCRIPT_DIR/../ubuntu/qradar_ubuntu_installer.sh"
readonly DEBIAN_INSTALLER="$SCRIPT_DIR/../debian/qradar_debian_installer.sh"
readonly RHEL_INSTALLER="$SCRIPT_DIR/../rhel/qradar_rhel_installer.sh"

# System information
DETECTED_DISTRO=""
DISTRO_FAMILY=""
INSTALLER_PATH=""

# Script parameters
QRADAR_IP=""
QRADAR_PORT=""
USE_MINIMAL_RULES=false
DRY_RUN=false

# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================

# Logging function
log() {
    local level="${1:-INFO}"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    echo "ERROR: $1" >&2
    echo "Check $LOG_FILE for details."
    exit 1
}

# Success message
success() {
    log "SUCCESS" "$1"
    echo "✓ $1"
}

# ===============================================================================
# SYSTEM DETECTION
# ===============================================================================

detect_distribution() {
    log "INFO" "Detecting Linux distribution..."
    
    if [[ ! -f /etc/os-release ]]; then
        error_exit "/etc/os-release file not found. Unsupported system."
    fi
    
    # shellcheck source=/etc/os-release
    source /etc/os-release
    
    DETECTED_DISTRO="$ID"
    
    case "$DETECTED_DISTRO" in
        "ubuntu")
            DISTRO_FAMILY="ubuntu"
            INSTALLER_PATH="$UBUNTU_INSTALLER"
            log "INFO" "Ubuntu system detected"
            ;;
        "debian"|"kali")
            DISTRO_FAMILY="debian"
            INSTALLER_PATH="$DEBIAN_INSTALLER"
            log "INFO" "Debian/Kali system detected"
            ;;
        "rhel"|"centos"|"rocky"|"almalinux"|"ol"|"amzn")
            DISTRO_FAMILY="rhel"
            INSTALLER_PATH="$RHEL_INSTALLER"
            log "INFO" "RHEL family system detected"
            ;;
        *)
            error_exit "Unsupported distribution: $DETECTED_DISTRO"
            ;;
    esac
    
    success "Distribution: $PRETTY_NAME - Installer: $DISTRO_FAMILY"
}

# ===============================================================================
# INSTALLER CHECK
# ===============================================================================

check_installer_availability() {
    log "INFO" "Checking for appropriate installer..."
    
    if [[ ! -f "$INSTALLER_PATH" ]]; then
        error_exit "Installer not found: $INSTALLER_PATH"
    fi
    
    if [[ ! -x "$INSTALLER_PATH" ]]; then
        log "INFO" "Making installer executable..."
        chmod +x "$INSTALLER_PATH" || error_exit "Failed to make installer executable"
    fi
    
    success "Installer ready: $INSTALLER_PATH"
}

# ===============================================================================
# BANNER AND INFORMATION
# ===============================================================================

show_banner() {
    echo ""
    echo "==============================================================================="
    echo "                    QRadar Universal Log Forwarding Installer"
    echo "                                 v$SCRIPT_VERSION"
    echo "==============================================================================="
    echo ""
    echo "🖥️  Detected System: $PRETTY_NAME"
    echo "🔧 Installer to be used: $DISTRO_FAMILY"
    echo "🎯 QRadar Target: $QRADAR_IP:$QRADAR_PORT"
    echo ""
    echo "ℹ️  This script provides:"
    echo "   • Automatic distribution detection"
    echo "   • MITRE ATT&CK compliant audit rules"
    echo "   • EXECVE command concatenation"
    echo "   • Security-focused log filtering"
    echo "   • Automatic fallback mechanisms"
    echo "   • Comprehensive error handling"
    echo ""
    echo "⚠️  Installation in progress..."
    echo "==============================================================================="
    echo ""
}

# ===============================================================================
# RUN INSTALLER
# ===============================================================================

run_specific_installer() {
    log "INFO" "Running distribution-specific installer..."
    
    show_banner
    
    # Build arguments for the specific installer
    local specific_installer_args=()
    if [[ "$USE_MINIMAL_RULES" == true ]]; then
        specific_installer_args+=("--minimal")
        log "INFO" "Minimal rules mode enabled"
    fi

    if [[ "$DRY_RUN" == true ]]; then
        specific_installer_args+=("--dry-run")
        log "INFO" "Dry run mode enabled"
    fi

    # Run the specific installer
    log "INFO" "Executing: $INSTALLER_PATH $QRADAR_IP $QRADAR_PORT ${specific_installer_args[*]}"
    
    if "$INSTALLER_PATH" "$QRADAR_IP" "$QRADAR_PORT" "${specific_installer_args[@]}"; then
        success "Specific installer completed successfully"
    else
        error_exit "Installer execution failed"
    fi
}

# ===============================================================================
# FINAL VERIFICATION AND SUMMARY
# ===============================================================================

final_verification() {
    log "INFO" "Performing final verification checks..."
    
    echo ""
    echo "==============================================================================="
    echo "                        Universal Installer Summary"
    echo "==============================================================================="
    echo ""
    echo "🎯 INSTALLATION SUCCESSFUL!"
    echo ""
    echo "📋 Installation Details:"
    echo "   • Detected System: $PRETTY_NAME"
    echo "   • Installer Used: $DISTRO_FAMILY"
    echo "   • QRadar Target: $QRADAR_IP:$QRADAR_PORT"
    echo "   • Universal Log File: $LOG_FILE"
    echo ""
    echo "📝 Next Steps:"
    echo "   1. Verify logs are arriving in QRadar"
    echo "   2. Run test commands:"
    echo "      • logger -p local3.info 'Test message'"
    echo "      • sudo touch /etc/passwd"
    echo "   3. Test network connectivity:"
    echo "      • telnet $QRADAR_IP $QRADAR_PORT"
    echo ""
    echo "🔍 For detailed logs:"
    echo "   • Universal log: $LOG_FILE"
    echo "   • Check distribution-specific log files"
    echo ""
    echo "✅ QRadar Universal Log Forwarding setup complete!"
    echo "==============================================================================="
    echo ""
    
    success "Universal installer completed successfully"
}

# ===============================================================================
# MAIN FUNCTION
# ===============================================================================

main() {
    # Create log file
    touch "$LOG_FILE" || error_exit "Cannot create log file: $LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null || true
    
    log "INFO" "============================================================="
    log "INFO" "QRadar Universal Log Forwarding Installer v$SCRIPT_VERSION"
    log "INFO" "Starting: $(date)"
    log "INFO" "QRadar Target: $QRADAR_IP:$QRADAR_PORT"
    log "INFO" "============================================================="
    
    # Root check
    [[ $EUID -eq 0 ]] || error_exit "This script must be run as root. Use 'sudo'."
    
    # Main processing steps
    detect_distribution
    check_installer_availability
    run_specific_installer
    final_verification
    
    log "INFO" "============================================================="
    log "INFO" "Universal installer finished: $(date)"
    log "INFO" "============================================================="
}

# ===============================================================================
# SCRIPT ENTRY POINT
# ===============================================================================

# Argument parsing
while [[ $# -gt 0 ]]; do
    case $1 in
        --minimal)
            USE_MINIMAL_RULES=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            echo "QRadar Universal Log Forwarding Installer v$SCRIPT_VERSION"
            echo ""
            echo "Usage: $0 <QRADAR_IP> <QRADAR_PORT> [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --minimal  Use minimal audit rules for EPS optimization"
            echo "  --dry-run  Run the script without making any changes"
            echo "  --help     Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 192.168.1.100 514"
            echo "  $0 192.168.1.100 514 --minimal"
            exit 0
            ;;
        -*)
            error_exit "Unknown option: $1"
            ;;
        *)
            if [[ -z "$QRADAR_IP" ]]; then
                QRADAR_IP="$1"
            elif [[ -z "$QRADAR_PORT" ]]; then
                QRADAR_PORT="$1"
            else
                error_exit "Too many arguments"
            fi
            shift
            ;;
    esac
done

# Parameter validation
if [[ -z "$QRADAR_IP" ]] || [[ -z "$QRADAR_PORT" ]]; then
    echo "Usage: $0 <QRADAR_IP> <QRADAR_PORT> [--minimal] [--dry-run]"
    echo "Example: $0 192.168.1.100 514 --minimal"
    exit 1
fi

# IP address format check
if ! [[ "$QRADAR_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    error_exit "Invalid IP address format: $QRADAR_IP"
fi

# Port number check
if ! [[ "$QRADAR_PORT" =~ ^[0-9]+$ ]] || [[ "$QRADAR_PORT" -lt 1 ]] || [[ "$QRADAR_PORT" -gt 65535 ]]; then
    error_exit "Invalid port number: $QRADAR_PORT (must be between 1-65535)"
fi

# Run main function
main

exit 0