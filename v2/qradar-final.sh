#!/usr/bin/env bash
#
# QRadar Unified Log Forwarding Setup Script v4.5 

set -euo pipefail

# =================== GLOBAL CONFIGURATION ===================
readonly SCRIPT_VERSION="4.5"
readonly LOG_FILE="/var/log/qradar_unified_setup.log"
readonly PYTHON_SCRIPT_PATH="/usr/local/bin/qradar_execve_parser.py"
readonly AUDIT_RULES_FILE="/etc/audit/rules.d/10-qradar-mitre.rules"
readonly AUDISP_PLUGIN_CONF="/etc/audisp/plugins.d/syslog.conf"
readonly RSYSLOG_SIEM_CONF="/etc/rsyslog.d/10-qradar-siem.conf"
readonly AUDIT_FACILITY="local6"
readonly BACKUP_SUFFIX="qradar-bak-$(date +%Y%m%d-%H%M%S)"
readonly AUDIT_LOG_FILE="/var/log/audit/audit.log"

# Platform detection variables
DISTRO=""
DISTRO_FAMILY=""
VERSION_ID_NUM=""
PACKAGE_MANAGER=""
SERVICE_MANAGER="systemctl"
AUDISP_AVAILABLE=true # Varsayılan olarak true, kontrol sonrası güncellenir.

# Tracking arrays
declare -a MODIFIED_FILES=()
declare -a CREATED_FILES=()
declare -a BACKUP_FILES=()
declare -a INSTALLED_PACKAGES=()
declare -a ENABLED_SERVICES=()
declare -a FIREWALL_RULES_ADDED=()
declare -a CRON_ENTRIES=()


# =================== UTILITY FUNCTIONS ===================

log() {
    local level="${2:-INFO}"
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $1"
    echo "$message" | tee -a "$LOG_FILE" >&2
}

error_exit() {
    log "FATAL ERROR: $1. Betik sonlandırılıyor." "FATAL"
    exit 1
}

warn() {
    log "WARNING: $1" "WARN"
}

success() {
    log "SUCCESS: $1" "SUCCESS"
}

execute_cmd() {
    local cmd="$1"
    local description="${2:-Komut çalıştırılıyor}"
    
    log "Çalıştırılıyor: $cmd" "DEBUG"
    if eval "$cmd" >> "$LOG_FILE" 2>&1; then
        log "$description - BAŞARILI" "DEBUG"
        return 0
    else
        local exit_code=$?
        warn "$description - BAŞARISIZ (çıkış kodu: $exit_code)"
        return $exit_code
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

track_file_change() { local file="$1"; local type="$2"; case "$type" in created) CREATED_FILES+=("$file");; modified) MODIFIED_FILES+=("$file");; backup) BACKUP_FILES+=("$file");; esac; }
track_service_change() { local service="$1"; ENABLED_SERVICES+=("$service"); }
track_package_install() { local package="$1"; INSTALLED_PACKAGES+=("$package"); }

# =================== PREREQUISITE CHECKS ===================

check_prerequisites() {
    log "=== QRadar Unified Log Forwarding Setup v$SCRIPT_VERSION ==="
    
    if [ "$EUID" -ne 0 ]; then
        error_exit "Bu betik root yetkisiyle çalıştırılmalıdır. 'sudo' kullanın."
    fi
    
    if [ $# -lt 2 ]; then
        echo "Kullanım: $0 <SIEM_IP> <SIEM_PORT>" >&2
        error_exit "Gerekli parametreler eksik."
    fi

    if ! echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        error_exit "Geçersiz SIEM IP adresi: $1"
    fi
    
    if ! echo "$2" | grep -Eq '^[0-9]+$' || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
        error_exit "Geçersiz SIEM port numarası: $2"
    fi

    mkdir -p "$(dirname "$LOG_FILE")" && touch "$LOG_FILE" || {
        LOG_FILE="/tmp/qradar_setup_$(date +%s).log"
        touch "$LOG_FILE" || error_exit "Log dosyası oluşturulamıyor."
    }
    chmod 640 "$LOG_FILE" 2>/dev/null || warn "Log dosyası izinleri ayarlanamadı."
    
    success "Ön kontroller tamamlandı."
}

# =================== PLATFORM DETECTION ===================

detect_platform() {
    log "Platform ve dağıtım tespit ediliyor..."
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO="$ID"
        VERSION_ID_NUM="${VERSION_ID:-unknown}"
        
        # ID_LIKE, RHEL türevlerini (CentOS, Alma, Rocky) yakalamak için daha güvenilirdir.
        local family_check="${ID_LIKE:-$ID}"
        case "$family_check" in
            *debian*)
                DISTRO_FAMILY="debian"
                PACKAGE_MANAGER="apt"
                ;;
            *rhel*|*fedora*|centos)
                DISTRO_FAMILY="rhel"
                PACKAGE_MANAGER=$(command_exists dnf && echo "dnf" || echo "yum")
                ;;
            *suse*)
                DISTRO_FAMILY="suse"
                PACKAGE_MANAGER="zypper"
                ;;
            *)
                warn "Bilinmeyen dağıtım ailesi: $ID. Genel ayarlarla devam edilecek."
                DISTRO_FAMILY="unknown"
                ;;
        esac
    else
        error_exit "/etc/os-release dosyası bulunamadı. Platform tespit edilemiyor."
    fi
    
    if ! command_exists systemctl; then
        SERVICE_MANAGER="service"
        log "systemd bulunamadı, eski 'service' komutu kullanılacak."
    fi
    
    log "Platform tespit edildi: $DISTRO $VERSION_ID_NUM (Aile: $DISTRO_FAMILY)"
}

# =================== PACKAGE INSTALLATION (IMPROVED) ===================

is_package_installed() {
    local pkg_name="$1"
    case "$DISTRO_FAMILY" in
        debian) dpkg -s "$pkg_name" >/dev/null 2>&1 ;;
        rhel) rpm -q "$pkg_name" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

install_package() {
    local pkg_name="$1"
    local pkg_desc="$2"
    
    if is_package_installed "$pkg_name"; then
        log "$pkg_desc ($pkg_name) zaten kurulu, atlanıyor."
        return 0
    fi
    
    log "$pkg_desc ($pkg_name) kuruluyor..."
    case "$DISTRO_FAMILY" in
        debian)
            if execute_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y $pkg_name" "$pkg_desc kurulumu"; then
                track_package_install "$pkg_name"
                return 0
            fi
            ;;
        rhel)
            if execute_cmd "$PACKAGE_MANAGER install -y $pkg_name" "$pkg_desc kurulumu"; then
                track_package_install "$pkg_name"
                return 0
            fi
            ;;
        *)
            warn "Paket kurulumu için desteklenmeyen platform: $pkg_name"
            ;;
    esac
    return 1
}

install_packages() {
    log "Gerekli paketler kontrol ediliyor ve kuruluyor..."
    
    case "$DISTRO_FAMILY" in
        debian)
            execute_cmd "apt-get update -y" "Paket listesi güncelleme"
            install_package "auditd" "Audit Daemon"
            install_package "rsyslog" "Rsyslog Service"
            install_package "python3" "Python 3"
            if ! install_package "audispd-plugins" "Audispd Plugins"; then
                warn "audispd-plugins paketi kurulamadı, alternatif yönteme geçilecek."
                AUDISP_AVAILABLE=false
            fi
            ;;
        rhel)
            # RHEL'de audit paketi hem daemon'u hem de araçları içerir
            install_package "audit" "Audit Framework"
            install_package "rsyslog" "Rsyslog Service"
            install_package "python3" "Python 3"
            if ! install_package "audispd-plugins" "Audispd Plugins"; then
                warn "audispd-plugins paketi kurulamadı, alternatif yönteme geçilecek."
                AUDISP_AVAILABLE=false
            fi
            ;;
        *)
            warn "Bu platform için otomatik paket kurulumu desteklenmiyor."
            AUDISP_AVAILABLE=false
            ;;
    esac

    if ! command_exists auditd || ! command_exists rsyslogd; then
        error_exit "Kritik bileşenler (auditd, rsyslogd) kurulamadı veya bulunamadı."
    fi
    
    check_audisp_availability_final
    success "Paket kurulum ve kontrolü tamamlandı."
}

check_audisp_availability_final() {
    if [ "$AUDISP_AVAILABLE" = false ]; then
        log "Audisp kurulum sırasında kullanılamaz olarak işaretlendi. Alternatif yöntem kullanılacak." "INFO"
        return
    fi
    
    local audisp_conf="/etc/audisp/plugins.d/syslog.conf"
    if [ ! -d "$(dirname "$audisp_conf")" ]; then
        AUDISP_AVAILABLE=false
        log "Audisp eklenti dizini bulunamadı. Alternatif yöntem kullanılacak." "WARN"
    fi
}

# =================== PYTHON SCRIPT DEPLOYMENT ===================

deploy_python_script() {
    log "EXECVE argüman ayrıştırıcı betik (Python) dağıtılıyor..."
    
    local python_cmd=""
    if command_exists python3; then
        python_cmd="python3"
    elif command_exists python; then
        python_cmd="python"
    else
        warn "Python bulunamadı, EXECVE ayrıştırıcı dağıtılamıyor. Loglar daha az detaylı olacak."
        return 1
    fi
    
    if [ -f "$PYTHON_SCRIPT_PATH" ]; then
        cp "$PYTHON_SCRIPT_PATH" "${PYTHON_SCRIPT_PATH}.$BACKUP_SUFFIX" && track_file_change "${PYTHON_SCRIPT_PATH}.$BACKUP_SUFFIX" "backup"
    fi
    
    mkdir -p "$(dirname "$PYTHON_SCRIPT_PATH")" || {
        warn "Python betik dizini oluşturulamadı."
        return 1
    }
    
    cat > "$PYTHON_SCRIPT_PATH" << 'PYTHON_SCRIPT_EOF'
#!/usr/bin/env python3
""" QRadar EXECVE Argument Parser v4.5 """
import sys, re, signal

def signal_handler(signum, frame):
    sys.exit(0)

def parse_execve_line(line):
    if 'type=EXECVE' not in line:
        return line
    
    try:
        args = {}
        for match in re.finditer(r'a(\d+)="([^"]*)"', line):
            args[int(match.group(1))] = match.group(2)
            
        if not args:
            return line

        command_parts = [args[i] for i in sorted(args.keys())]
        full_command = ' '.join(filter(None, command_parts))
        
        # Gereksiz aX alanlarını temizle ve cmd alanını ekle
        cleaned_line = re.sub(r' a\d+="[^"]*"', '', line).strip()
        enhanced_line = f'{cleaned_line} cmd="{full_command}"'
        return enhanced_line
    except Exception:
        return line

def main():
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        for line in sys.stdin:
            processed_line = parse_execve_line(line.rstrip())
            sys.stdout.write(processed_line + '\n')
            sys.stdout.flush()
    except (IOError, BrokenPipeError):
        pass # rsyslog yeniden başlatıldığında oluşabilir, normaldir.
    except Exception as e:
        sys.stderr.write(f"EXECVE_PARSER_ERROR: {e}\n")
        sys.stderr.flush()

if __name__ == '__main__':
    main()
PYTHON_SCRIPT_EOF
    
    sed -i "1s|.*|#!$(command -v "$python_cmd")|" "$PYTHON_SCRIPT_PATH"
    chmod 755 "$PYTHON_SCRIPT_PATH"
    chown root:root "$PYTHON_SCRIPT_PATH" 2>/dev/null
    track_file_change "$PYTHON_SCRIPT_PATH" "created"
    
    if echo 'type=EXECVE msg=audit(123): a0="ls" a1="-la"' | "$PYTHON_SCRIPT_PATH" | grep -q 'cmd="ls -la"'; then
        success "Python EXECVE ayrıştırıcı başarıyla dağıtıldı ve test edildi."
    else
        warn "Python EXECVE ayrıştırıcı testi başarısız oldu."
    fi
}

# =================== AUDIT CONFIGURATION ===================

configure_auditd() {
    log "auditd yapılandırılıyor..."
    
    if ! command_exists auditctl; then
        warn "auditd sistemi bulunamadı, audit yapılandırması atlanıyor."
        return 1
    fi
    
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")" || {
        warn "Audit kuralları dizini oluşturulamadı."
        return 1
    }
    
    if [ -f "$AUDIT_RULES_FILE" ]; then
        cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.$BACKUP_SUFFIX" && track_file_change "${AUDIT_RULES_FILE}.$BACKUP_SUFFIX" "backup"
    fi
    
    cat > "$AUDIT_RULES_FILE" << 'AUDIT_RULES_EOF'
# QRadar MITRE ATT&CK Aligned Audit Rules v4.5 - Optimized
-D
-b 8192
-f 1
--backlog_wait_time 60000
-r 100

# Kimlik Bilgileri ve Yetkilendirme
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Yetki Yükseltme
-a always,exit -F arch=b64 -S setuid -F auid>=1000 -F auid!=4294967295 -k privilege_escalation
-a always,exit -F arch=b32 -S setuid -F auid>=1000 -F auid!=4294967295 -k privilege_escalation

# Root Komutları
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_command
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_command

# Sistem Bütünlüğü ve Kalıcılık
-w /sbin/insmod -p x -k kernel_module
-w /sbin/modprobe -p x -k kernel_module
-w /sbin/rmmod -p x -k kernel_module
-w /etc/crontab -p wa -k persistence
-w /etc/cron.d/ -p wa -k persistence
-w /var/spool/cron/ -p wa -k persistence

# Ağ Yapılandırması
-w /etc/hosts -p wa -k network_mod
-w /etc/resolv.conf -p wa -k network_mod
AUDIT_RULES_EOF
    chmod 640 "$AUDIT_RULES_FILE"
    track_file_change "$AUDIT_RULES_FILE" "created"
    
    if [ "$AUDISP_AVAILABLE" = true ]; then
        configure_audisp_plugin
    else
        log "Audisp kullanılamıyor, doğrudan audit log iletimi (alternatif yöntem) yapılandırılıyor."
        configure_audit_direct_logging
    fi
}

configure_audisp_plugin() {
    log "audisp-syslog eklentisi yapılandırılıyor..."
    cat > "$AUDISP_PLUGIN_CONF" << EOF
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_LOCAL6
format = string
EOF
    chmod 640 "$AUDISP_PLUGIN_CONF"
    track_file_change "$AUDISP_PLUGIN_CONF" "created"
    success "Audisp eklentisi yapılandırıldı."
}

configure_audit_direct_logging() {
    local audit_forwarder="/usr/local/bin/audit_to_rsyslog.sh"
    cat > "$audit_forwarder" << 'EOF'
#!/bin/bash
AUDIT_LOG="/var/log/audit/audit.log"
LAST_POS_FILE="/var/run/audit_forwarder.pos"
exec 200>"/var/run/audit_forwarder.lock"
flock -n 200 || exit 0
trap 'flock -u 200' EXIT

touch "$LAST_POS_FILE"
LAST_POS=$(cat "$LAST_POS_FILE" 2>/dev/null || echo 0)
[[ "$LAST_POS" =~ ^[0-9]+$ ]] || LAST_POS=0

[ -f "$AUDIT_LOG" ] || exit 0
CURRENT_SIZE=$(stat -c%s "$AUDIT_LOG")
[ "$CURRENT_SIZE" -lt "$LAST_POS" ] && LAST_POS=0

if [ "$CURRENT_SIZE" -gt "$LAST_POS" ]; then
    tail -c "+$((LAST_POS + 1))" "$AUDIT_LOG" | head -n 1000 | while IFS= read -r line; do
        logger -p local6.info -t audit -- "$line"
    done
    echo "$CURRENT_SIZE" > "$LAST_POS_FILE"
fi
EOF
    chmod 755 "$audit_forwarder"
    track_file_change "$audit_forwarder" "created"
    
    local cron_entry="* * * * * $audit_forwarder"
    (crontab -l 2>/dev/null | grep -v "$audit_forwarder"; echo "$cron_entry") | crontab -
    CRON_ENTRIES+=("$cron_entry")
    log "Alternatif log iletimi için cron görevi eklendi."
}

load_audit_rules() {
    log "Audit kuralları yükleniyor..."
    
    if [[ "$DISTRO_FAMILY" == "rhel" ]] && [[ "$VERSION_ID_NUM" =~ ^7 ]]; then
        log "RHEL 7 tespit edildi, 'service auditd reload' kullanılacak."
        execute_cmd "service auditd reload" "auditd servisinin yeniden yüklenmesi (RHEL 7)" || {
            warn "'service auditd reload' başarısız oldu. Kurallar manuel yükleniyor."
            execute_cmd "auditctl -R '$AUDIT_RULES_FILE'" "Audit kurallarının manuel yüklenmesi"
        }
    else
        execute_cmd "augenrules --load" "augenrules ile kuralların yüklenmesi" || {
            warn "augenrules başarısız, auditctl ile deneniyor."
            execute_cmd "auditctl -R '$AUDIT_RULES_FILE'" "auditctl ile kuralların yüklenmesi"
        }
        log "auditd servisi yeniden başlatılıyor..."
        execute_cmd "$SERVICE_MANAGER restart auditd" "auditd servisinin yeniden başlatılması" || warn "auditd yeniden başlatılamadı."
    fi
    
    sleep 2
    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | wc -l)
    if [ "$rule_count" -gt 5 ]; then
        success "Audit kuralları başarıyla yüklendi ($rule_count kural aktif)."
    else
        warn "Audit kuralları yüklenmemiş görünüyor. Lütfen '$LOG_FILE' dosyasını ve 'auditctl -s' çıktısını kontrol edin."
    fi
}

# =================== RSYSLOG CONFIGURATION ===================

configure_rsyslog() {
    log "rsyslog, QRadar SIEM iletimi için yapılandırılıyor..."
    local siem_ip="$1"
    local siem_port="$2"
    
    if [ -f "$RSYSLOG_SIEM_CONF" ]; then
        cp "$RSYSLOG_SIEM_CONF" "${RSYSLOG_SIEM_CONF}.$BACKUP_SUFFIX" && track_file_change "${RSYSLOG_SIEM_CONF}.$BACKUP_SUFFIX" "backup"
    fi
    
    local use_python_parser=false
    [ -x "$PYTHON_SCRIPT_PATH" ] && use_python_parser=true
    
    # RainerScript formatında modern ve sağlam bir yapılandırma
    cat > "$RSYSLOG_SIEM_CONF" << EOF
# QRadar SIEM Forwarding Configuration v4.5
module(load="imklog")
module(load="omfwd")
$( [ "$use_python_parser" = true ] && echo 'module(load="omprog")' )

# Güvenilir iletim için ana eylem kuyruğu
main_queue(
  queue.type="linkedlist"
  queue.filename="qradar_main_queue"
  queue.maxdiskspace="1g"
  queue.saveonshutdown="on"
  queue.timeoutenqueue="0"
)

template(name="QRadarFormat" type="string" string="<%PRI%>%TIMESTAMP% %HOSTNAME% %APP-NAME%[%PROCID%]: %MSG%\\n")

# --- KURAL SETLERİ ---

# KURALSET: Audit loglarını işle ve yönlendir
ruleset(name="qradar_audit") {
    if \$msg contains "type=EXECVE" and $use_python_parser then {
        action(
            type="omprog"
            binary="$PYTHON_SCRIPT_PATH"
            template="RSYSLOG_TraditionalFileFormat"
            name="execve_parser"
        )
    }
    
    action(
        type="omfwd"
        target="$siem_ip" port="$siem_port" protocol="tcp"
        template="QRadarFormat"
        action.resumeRetryCount="-1"
        queue.filename="qradar_audit_fwd"
        queue.maxdiskspace="500m"
        queue.saveonshutdown="on"
    )
    stop
}

# KURALSET: Diğer önemli güvenlik loglarını yönlendir
ruleset(name="qradar_security") {
    action(
        type="omfwd"
        target="$siem_ip" port="$siem_port" protocol="tcp"
        template="QRadarFormat"
        action.resumeRetryCount="-1"
        queue.filename="qradar_security_fwd"
        queue.maxdiskspace="200m"
        queue.saveonshutdown="on"
    )
    stop
}

# --- ANA FİLTRELEME MANTIĞI ---

# 1. Audit loglarını (local6) özel kural setine yönlendir
if \$syslogfacility-text == '$AUDIT_FACILITY' then {
    call qradar_audit
}

# 2. Diğer güvenlik loglarını (auth, authpriv, vb.) yönlendir
if \$syslogfacility-text == 'auth' or \$syslogfacility-text == 'authpriv' or
   (\$programname == 'sudo' or \$programname == 'su')
then {
    call qradar_security
}

# 3. Bilinen gürültülü logları en başta engelle
if (\$programname == 'systemd' and (\$msg contains 'Started Session' or \$msg contains 'Created slice' or \$msg contains 'Removed slice')) or
   \$programname == 'CRON' or \$programname contains 'dhclient' or \$programname == 'dbus-daemon'
then {
    stop
}
EOF

    track_file_change "$RSYSLOG_SIEM_CONF" "created"
    
    log "Rsyslog yapılandırması kontrol ediliyor..."
    if rsyslogd -N1 >/dev/null 2>&1; then
        success "Rsyslog yapılandırması geçerli."
        execute_cmd "$SERVICE_MANAGER restart rsyslog" "Rsyslog servisi yeniden başlatılıyor"
    else
        warn "Rsyslog yapılandırması geçersiz. Lütfen '$LOG_FILE' dosyasını kontrol edin. Değişiklikler geri alınıyor."
        [ -f "${RSYSLOG_SIEM_CONF}.$BACKUP_SUFFIX" ] && mv "${RSYSLOG_SIEM_CONF}.$BACKUP_SUFFIX" "$RSYSLOG_SIEM_CONF"
        execute_cmd "$SERVICE_MANAGER restart rsyslog" "Rsyslog servisi eski yapılandırma ile yeniden başlatılıyor"
        return 1
    fi
}

# =================== FIREWALL CONFIGURATION (NEW) ===================

configure_firewall() {
    local siem_port="$1"
    log "Güvenlik duvarı kuralları kontrol ediliyor..."
    
    if [[ "$DISTRO_FAMILY" == "rhel" ]] && command_exists firewall-cmd && systemctl is-active --quiet firewalld; then
        log "firewalld aktif, SIEM portu ($siem_port/tcp) için kural ekleniyor..."
        if ! firewall-cmd --query-port="$siem_port/tcp" --permanent > /dev/null 2>&1; then
            execute_cmd "firewall-cmd --add-port=$siem_port/tcp --permanent" "Firewall kuralı ekleme"
            execute_cmd "firewall-cmd --reload" "Firewall kurallarını yeniden yükleme"
            FIREWALL_RULES_ADDED+=("firewalld: Port $siem_port/tcp eklendi")
            success "Firewall kuralı başarıyla eklendi."
        else
            log "Firewall kuralı ($siem_port/tcp) zaten mevcut."
        fi
    elif [[ "$DISTRO_FAMILY" == "debian" ]] && command_exists ufw && ufw status | grep -q "Status: active"; then
        log "UFW aktif, SIEM portu ($siem_port/tcp) için kural ekleniyor..."
        if ! ufw status | grep -q "$siem_port/tcp"; then
            execute_cmd "ufw allow out $siem_port/tcp" "UFW giden kuralı ekleme"
            FIREWALL_RULES_ADDED+=("ufw: Giden Port $siem_port/tcp için izin verildi")
            success "UFW kuralı başarıyla eklendi."
        else
            log "UFW kuralı ($siem_port/tcp) zaten mevcut."
        fi
    else
        warn "Otomatik güvenlik duvarı yapılandırması yapılamadı. Lütfen giden $siem_port/tcp trafiğine manuel olarak izin verin."
    fi
}

# =================== TESTING & FINAL REPORT ===================

test_configuration() {
    log "Yapılandırma test ediliyor..."
    logger -p ${AUDIT_FACILITY}.info "TEST: QRadar audit test from $(hostname) at $(date)"
    logger -p auth.info "TEST: QRadar auth test - sudo command execution test"
    log "Test logları oluşturuldu. Lütfen QRadar konsolunu kontrol edin."
}

generate_final_report() {
    local siem_ip="$1"
    local siem_port="$2"
    local report_file="/root/qradar_setup_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "========================================================================="
        echo "           QRadar Unified Log Forwarding Setup Report (v$SCRIPT_VERSION)"
        echo "========================================================================="
        echo "Tarih: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Hostname: $(hostname)"
        echo "İşletim Sistemi: $DISTRO $VERSION_ID_NUM ($DISTRO_FAMILY)"
        echo "Hedef SIEM: $siem_ip:$siem_port"
        echo "-------------------------------------------------------------------------"
        echo ""
        echo ">> KURULUM ÖZETİ"
        echo "Log İletim Yöntemi: $([ "$AUDISP_AVAILABLE" = true ] && echo "Audisp Plugin (Önerilen)" || echo "Doğrudan İletim (Cron Tabanlı Alternatif)")"
        
        echo ""
        echo ">> KURULAN PAKETLER"
        if [ ${#INSTALLED_PACKAGES[@]} -eq 0 ]; then
            echo "  - Yeni paket kurulmadı, tümü mevcuttu."
        else
            for pkg in "${INSTALLED_PACKAGES[@]}"; do echo "  - $pkg"; done
        fi

        echo ""
        echo ">> OLUŞTURULAN/DEĞİŞTİRİLEN DOSYALAR"
        for file in "${CREATED_FILES[@]}" "${MODIFIED_FILES[@]}"; do echo "  - $file"; done

        echo ""
        echo ">> GÜVENLİK DUVARI VE SELINUX"
        if [ ${#FIREWALL_RULES_ADDED[@]} -eq 0 ]; then
            echo "  - Güvenlik Duvarı: Otomatik kural eklenmedi. Port $siem_port/tcp için manuel kontrol yapın."
        else
            for rule in "${FIREWALL_RULES_ADDED[@]}"; do echo "  - Güvenlik Duvarı: $rule"; done
        fi

        if [[ "$DISTRO_FAMILY" == "rhel" ]] && command_exists getenforce; then
            echo "  - SELinux Durumu: $(getenforce)"
            if [[ "$(getenforce)" == "Enforcing" ]]; then
                echo "    - UYARI: SELinux 'Enforcing' modda. Gerekirse 'setsebool -P nis_enabled 1' komutunu çalıştırın."
            fi
        fi
        
        echo ""
        echo ">> SONRAKİ ADIMLAR"
        echo "1. QRadar konsolundan '$siem_ip' IP adresinden gelen logları kontrol edin."
        echo "2. Sorun yaşarsanız, detaylı log dosyasını inceleyin: $LOG_FILE"
        echo "3. Yapılandırmayı geri almak için yedeklenen dosyaları kullanın ('.${BACKUP_SUFFIX}' uzantılı)."
        echo "   Örnek: mv /etc/rsyslog.d/10-qradar-siem.conf.${BACKUP_SUFFIX} /etc/rsyslog.d/10-qradar-siem.conf"
        
        echo ""
        echo "========================================================================="
        echo "KURULUM TAMAMLANDI"
        echo "========================================================================="

    } | tee "$report_file"
    
    log "Detaylı rapor şuraya kaydedildi: $report_file"
}

# =================== MAIN EXECUTION ===================

main() {
    check_prerequisites "$@"
    
    local siem_ip="$1"
    local siem_port="$2"
    
    detect_platform
    install_packages
    deploy_python_script
    configure_auditd
    load_audit_rules
    configure_rsyslog "$siem_ip" "$siem_port"
    configure_firewall "$siem_port"
    test_configuration
    
    generate_final_report "$siem_ip" "$siem_port"
}

# Betiği doğrudan çalıştır
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
