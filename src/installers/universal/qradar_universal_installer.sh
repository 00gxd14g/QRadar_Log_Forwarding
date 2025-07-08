#!/usr/bin/env bash
#
# ===============================================================================
# QRadar Universal Log Forwarding Installer v4.0.0
# ===============================================================================
#
# Bu script, tüm Linux dağıtımlarında çalışacak şekilde tasarlanmış
# evrensel QRadar SIEM log iletimi kurulum scriptıdir.
#
# Desteklenen Tüm Dağıtımlar:
#   • Ubuntu (16.04+)
#   • Debian (9+)
#   • RHEL/CentOS (7+)
#   • Rocky Linux (8+)
#   • AlmaLinux (8+)
#   • Oracle Linux (7+)
#   • Amazon Linux 2
#   • Kali Linux
#
# Özellikler:
#   - Otomatik dağıtım tespiti ve uygun installer seçimi
#   - Unified yapılandırma approach
#   - Kapsamlı güvenlik monitoring
#   - MITRE ATT&CK uyumlu kurallar
#   - Güvenli komut çalıştırma
#   - Comprehensive error handling
#
# Kullanım: sudo bash qradar_universal_installer.sh <QRADAR_IP> <QRADAR_PORT>
#
# Yazar: QRadar Log Forwarding Projesi
# Sürüm: 4.0.0 - Universal Edition
# ===============================================================================

set -euo pipefail

# ===============================================================================
# GLOBAL DEĞIŞKENLER
# ===============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="4.0.0-universal"
readonly LOG_FILE="/var/log/qradar_universal_setup.log"

# Script directory
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Installer paths
readonly UBUNTU_INSTALLER="$SCRIPT_DIR/../ubuntu/qradar_ubuntu_installer.sh"
readonly DEBIAN_INSTALLER="$SCRIPT_DIR/../debian/qradar_debian_installer.sh"
readonly RHEL_INSTALLER="$SCRIPT_DIR/../rhel/qradar_rhel_installer.sh"

# Sistem bilgileri
DETECTED_DISTRO=""
DISTRO_FAMILY=""
INSTALLER_PATH=""

# Script parametreleri
QRADAR_IP=""
QRADAR_PORT=""

# ===============================================================================
# YARDIMCI FONKSİYONLAR
# ===============================================================================

# Logging fonksiyonu
log() {
    local level="${1:-INFO}"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Hata yönetimi
error_exit() {
    log "ERROR" "$1"
    echo "HATA: $1" >&2
    echo "Detaylar için $LOG_FILE dosyasını kontrol edin."
    exit 1
}

# Başarı mesajı
success() {
    log "SUCCESS" "$1"
    echo "✓ $1"
}

# ===============================================================================
# SİSTEM TESPİTİ
# ===============================================================================

detect_distribution() {
    log "INFO" "Linux dağıtımı tespit ediliyor..."
    
    if [[ ! -f /etc/os-release ]]; then
        error_exit "/etc/os-release dosyası bulunamadı. Desteklenmeyen sistem."
    fi
    
    # shellcheck source=/etc/os-release
    source /etc/os-release
    
    DETECTED_DISTRO="$ID"
    
    case "$DETECTED_DISTRO" in
        "ubuntu")
            DISTRO_FAMILY="ubuntu"
            INSTALLER_PATH="$UBUNTU_INSTALLER"
            log "INFO" "Ubuntu sistemi tespit edildi"
            ;;
        "debian"|"kali")
            DISTRO_FAMILY="debian"
            INSTALLER_PATH="$DEBIAN_INSTALLER"
            log "INFO" "Debian/Kali sistemi tespit edildi"
            ;;
        "rhel"|"centos"|"rocky"|"almalinux"|"ol"|"amzn")
            DISTRO_FAMILY="rhel"
            INSTALLER_PATH="$RHEL_INSTALLER"
            log "INFO" "RHEL ailesi sistemi tespit edildi"
            ;;
        *)
            error_exit "Desteklenmeyen dağıtım: $DETECTED_DISTRO"
            ;;
    esac
    
    success "Dağıtım: $PRETTY_NAME - Installer: $DISTRO_FAMILY"
}

# ===============================================================================
# INSTALLER KONTROLÜ
# ===============================================================================

check_installer_availability() {
    log "INFO" "Uygun installer kontrol ediliyor..."
    
    if [[ ! -f "$INSTALLER_PATH" ]]; then
        error_exit "Installer bulunamadı: $INSTALLER_PATH"
    fi
    
    if [[ ! -x "$INSTALLER_PATH" ]]; then
        log "INFO" "Installer çalıştırılabilir yapılıyor..."
        chmod +x "$INSTALLER_PATH" || error_exit "Installer çalıştırılabilir yapılamadı"
    fi
    
    success "Installer hazır: $INSTALLER_PATH"
}

# ===============================================================================
# BANNER VE BİLGİLER
# ===============================================================================

show_banner() {
    echo ""
    echo "==============================================================================="
    echo "                    QRadar Universal Log Forwarding Installer"
    echo "                                 v$SCRIPT_VERSION"
    echo "==============================================================================="
    echo ""
    echo "🖥️  Tespit Edilen Sistem: $PRETTY_NAME"
    echo "🔧 Kullanılacak Installer: $DISTRO_FAMILY"
    echo "🎯 QRadar Hedefi: $QRADAR_IP:$QRADAR_PORT"
    echo ""
    echo "ℹ️  Bu script şu özellikleri sağlar:"
    echo "   • Otomatik dağıtım tespiti"
    echo "   • MITRE ATT&CK uyumlu audit kuralları"
    echo "   • EXECVE komut birleştirme"
    echo "   • Güvenlik odaklı log filtreleme"
    echo "   • Otomatik fallback mekanizmaları"
    echo "   • Comprehensive error handling"
    echo ""
    echo "⚠️  Kurulum devam ediyor..."
    echo "==============================================================================="
    echo ""
}

# ===============================================================================
# INSTALLER ÇALIŞTIRMA
# ===============================================================================

run_specific_installer() {
    log "INFO" "Dağıtıma özel installer çalıştırılıyor..."
    
    show_banner
    
    # Specific installer'ı çalıştır
    log "INFO" "Çalıştırılıyor: $INSTALLER_PATH $QRADAR_IP $QRADAR_PORT"
    
    if "$INSTALLER_PATH" "$QRADAR_IP" "$QRADAR_PORT"; then
        success "Dağıtıma özel installer başarıyla tamamlandı"
    else
        error_exit "Installer çalıştırma başarısız oldu"
    fi
}

# ===============================================================================
# SON KONTROLLER VE ÖZET
# ===============================================================================

final_verification() {
    log "INFO" "Final doğrulama kontrolleri yapılıyor..."
    
    echo ""
    echo "==============================================================================="
    echo "                        Universal Installer Özeti"
    echo "==============================================================================="
    echo ""
    echo "🎯 KURULUM BAŞARILI!"
    echo ""
    echo "📋 Kurulum Detayları:"
    echo "   • Tespit Edilen Sistem: $PRETTY_NAME"
    echo "   • Kullanılan Installer: $DISTRO_FAMILY"
    echo "   • QRadar Hedefi: $QRADAR_IP:$QRADAR_PORT"
    echo "   • Universal Log Dosyası: $LOG_FILE"
    echo ""
    echo "📝 Sonraki Adımlar:"
    echo "   1. QRadar'da log'ların geldiğini kontrol edin"
    echo "   2. Test komutları çalıştırın:"
    echo "      • logger -p local3.info 'Test mesajı'"
    echo "      • sudo touch /etc/passwd"
    echo "   3. Ağ bağlantısını test edin:"
    echo "      • telnet $QRADAR_IP $QRADAR_PORT"
    echo ""
    echo "🔍 Detaylı loglar için:"
    echo "   • Universal log: $LOG_FILE"
    echo "   • Dağıtıma özel log dosyalarını kontrol edin"
    echo ""
    echo "✅ QRadar Universal Log Forwarding kurulumu tamamlandı!"
    echo "==============================================================================="
    echo ""
    
    success "Universal installer başarıyla tamamlandı"
}

# ===============================================================================
# MAIN FUNCTION
# ===============================================================================

main() {
    # Log dosyasını oluştur
    touch "$LOG_FILE" || error_exit "Log dosyası oluşturulamıyor: $LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null || true
    
    log "INFO" "============================================================="
    log "INFO" "QRadar Universal Log Forwarding Installer v$SCRIPT_VERSION"
    log "INFO" "Başlatılıyor: $(date)"
    log "INFO" "QRadar Hedefi: $QRADAR_IP:$QRADAR_PORT"
    log "INFO" "============================================================="
    
    # Root kontrolü
    [[ $EUID -eq 0 ]] || error_exit "Bu script root yetkisiyle çalıştırılmalıdır. 'sudo' kullanın."
    
    # Ana işlem adımları
    detect_distribution
    check_installer_availability
    run_specific_installer
    final_verification
    
    log "INFO" "============================================================="
    log "INFO" "Universal installer tamamlandı: $(date)"
    log "INFO" "============================================================="
}

# ===============================================================================
# SCRIPT ENTRY POINT
# ===============================================================================

# Parametre doğrulama
if [[ $# -ne 2 ]]; then
    echo ""
    echo "==============================================================================="
    echo "                    QRadar Universal Log Forwarding Installer"
    echo "                                 v$SCRIPT_VERSION"
    echo "==============================================================================="
    echo ""
    echo "Kullanım: $0 <QRADAR_IP> <QRADAR_PORT>"
    echo ""
    echo "Örnek: $0 192.168.1.100 514"
    echo ""
    echo "Desteklenen Dağıtımlar:"
    echo "  🐧 Ubuntu (16.04+)"
    echo "  🐧 Debian (9+)"
    echo "  🐧 RHEL/CentOS (7+)"
    echo "  🐧 Rocky Linux (8+)"
    echo "  🐧 AlmaLinux (8+)"
    echo "  🐧 Oracle Linux (7+)"
    echo "  🐧 Amazon Linux 2"
    echo "  🐧 Kali Linux"
    echo ""
    echo "Bu universal installer, sisteminizi otomatik olarak tespit eder"
    echo "ve uygun installer'ı çalıştırır."
    echo ""
    echo "==============================================================================="
    exit 1
fi

# IP adresi format kontrolü
if ! [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    error_exit "Geçersiz IP adresi formatı: $1"
fi

# Port numarası kontrolü
if ! [[ "$2" =~ ^[0-9]+$ ]] || [[ "$2" -lt 1 ]] || [[ "$2" -gt 65535 ]]; then
    error_exit "Geçersiz port numarası: $2 (1-65535 arası olmalı)"
fi

# Global değişkenleri ayarla
QRADAR_IP="$1"
QRADAR_PORT="$2"

# Ana fonksiyonu çalıştır
main

exit 0