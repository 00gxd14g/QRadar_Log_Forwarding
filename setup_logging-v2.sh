#!/bin/bash
set -e

# ------------------------------------------------------------------------------
# Auditd ve Rsyslog Yapılandırma Scripti
# (die.net man sayfalarına göre: auditd.conf(8), audispd(8), auditd(8))
# Kullanım: sudo bash setup_logging.sh <SIEM_IP> <SIEM_PORT>
# ------------------------------------------------------------------------------

# Global değişkenler
LOG_FILE="/var/log/setup_logging.log"
SYSLOG_CONF="/etc/rsyslog.d/00-siem.conf"
AUDITD_CONF="/etc/audit/auditd.conf"
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
AUDISP_CONF="/etc/audit/plugins.d/syslog.conf"
AUDITD_LOG_FILE="/var/log/audit/audit.log"

# Log dosyasının yazılabilir olduğundan emin ol
touch "$LOG_FILE" 2>/dev/null || { echo "HATA: $LOG_FILE dosyasına yazılamıyor" >&2; exit 1; }
chmod 640 "$LOG_FILE" 2>/dev/null || { echo "HATA: $LOG_FILE izinleri ayarlanamadı" >&2; exit 1; }

# Zaman damgalı log fonksiyonu
log() {
    local message
    message="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$message" | tee -a "$LOG_FILE" >/dev/null 2>&1 || {
        echo "HATA: Log dosyasına yazma başarısız: $message" >&2
        return 1
    }
    echo "$message"
}

error_exit() {
    log "HATA: $1"
    echo "HATA: $1" >&2
    exit 1
}

# Root kontrolü ve parametreler
[ "$EUID" -ne 0 ] && error_exit "Bu script root olarak çalıştırılmalı. sudo kullanın."
[ $# -lt 2 ] && { echo "Kullanım: $0 <SIEM_IP> <SIEM_PORT>" >&2; exit 1; }

SIEM_IP="$1"
SIEM_PORT="$2"
log "Yapılandırma başlıyor - SIEM IP: $SIEM_IP, Port: $SIEM_PORT"

# Dağıtım tespiti
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    VERSION_ID=$VERSION_ID
else
    DISTRO=$(uname -s)
    VERSION_ID=$(uname -r)
fi

case "$DISTRO" in
    ubuntu|debian|kali) SYSLOG_FILE="/var/log/syslog";;
    rhel|centos|oracle) SYSLOG_FILE="/var/log/messages";;
    *) error_exit "Desteklenmeyen dağıtım: $DISTRO";;
esac

log "Tespit edildi: $DISTRO $VERSION_ID, Syslog: $SYSLOG_FILE"

# Paket kurulumu
install_packages() {
    log "Gerekli paketler kuruluyor..."
    case "$DISTRO" in
        ubuntu|debian|kali)
            apt-get update >> "$LOG_FILE" 2>&1 || error_exit "apt-get update başarısız"
            apt-get install -y auditd audispd-plugins rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Paket kurulumu başarısız"
            ;;
        rhel|centos|oracle)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y audit rsyslog >> "$LOG_FILE" 2>&1 || error_exit "dnf kurulumu başarısız"
            else
                yum install -y audit rsyslog >> "$LOG_FILE" 2>&1 || error_exit "yum kurulumu başarısız"
            fi
            ;;
    esac
}

install_packages || error_exit "Paket kurulumu başarısız"
log "Paketler başarıyla kuruldu"

# Auditd yapılandırması
configure_auditd() {
    log "auditd yapılandırılıyor..."
    
    # auditd.conf yedeği alınır ama log_facility değiştirilmez
    [ -f "$AUDITD_CONF" ] && cp "$AUDITD_CONF" "${AUDITD_CONF}.bak" 2>/dev/null || log "UYARI: $AUDITD_CONF yedeklenemedi"
    log "auditd.conf dosyası 'log_facility' parametresi desteklemediğinden değiştirilmiyor."
    
    # Audit kuralları dizini oluşturulur
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")" || error_exit "Audit kuralları dizini oluşturulamadı"
    
    [ -f "$AUDIT_RULES_FILE" ] && cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.bak" 2>/dev/null || log "UYARI: $AUDIT_RULES_FILE yedeklenemedi"
    
    # Audit kuralları yazılır
    cat > "$AUDIT_RULES_FILE" << 'EOF' || error_exit "Audit kuralları yazılamadı"
-D
-b 8192
-f 1
-i
-w /etc/audit/ -p wa -k auditconfig
-w /etc/passwd -p wa -k passwd_modifications
-w /etc/shadow -p wa -k passwd_modifications
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_command
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_command
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
-w /etc/hosts -p wa -k network_modifications
-w /sbin/shutdown -p x -k system_state_modifications
-w /bin/su -p x -k su_execution
-w /usr/bin/sudo -p x -k sudo_execution
-e 2
EOF

    chmod 640 "$AUDIT_RULES_FILE" 2>/dev/null || error_exit "Audit kuralları izinleri ayarlanamadı"
    
    systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "auditd yeniden başlatılamadı"
    systemctl enable auditd >> "$LOG_FILE" 2>&1 || error_exit "auditd etkinleştirilemedi"
}

configure_auditd || error_exit "auditd yapılandırması başarısız"
log "auditd başarıyla yapılandırıldı"

# audisp-syslog yapılandırması
configure_audisp() {
    log "audisp-syslog yapılandırılıyor..."
    if [ -f "/usr/sbin/audisp-syslog" ]; then
        AUDISP_SYSLOG_PATH="/usr/sbin/audisp-syslog"
    elif [ -f "/usr/lib/audisp/audisp-syslog" ]; then
        AUDISP_SYSLOG_PATH="/usr/lib/audisp/audisp-syslog"
    else
        error_exit "audisp-syslog bulunamadı"
    fi
    
    mkdir -p "$(dirname "$AUDISP_CONF")" || error_exit "audisp config dizini oluşturulamadı"
    
    cat > "$AUDISP_CONF" << EOF || error_exit "audisp-syslog yapılandırılamadı"
active = yes
direction = out
path = $AUDISP_SYSLOG_PATH
type = always
args = LOG_LOCAL3
format = string
EOF
    
    chmod 640 "$AUDISP_CONF" 2>/dev/null || error_exit "audisp izinleri ayarlanamadı"
}

configure_audisp || error_exit "audisp yapılandırması başarısız"
log "audisp-syslog yapılandırıldı"

# rsyslog yapılandırması
configure_rsyslog() {
    log "rsyslog yapılandırılıyor..."
    [ -f "$SYSLOG_CONF" ] && cp "$SYSLOG_CONF" "${SYSLOG_CONF}.bak" 2>/dev/null || log "UYARI: $SYSLOG_CONF yedeklenemedi"
    
    cat > "$SYSLOG_CONF" << EOF || error_exit "rsyslog config yazılamadı"
if \$syslogfacility-text == "kern" then {
    stop
}
if \$syslogfacility-text == "local3" then {
    action(type="omfwd" target="$SIEM_IP" port="$SIEM_PORT" protocol="tcp")
    stop
}
EOF
    
    systemctl restart rsyslog >> "$LOG_FILE" 2>&1 || error_exit "rsyslog yeniden başlatılamadı"
    systemctl enable rsyslog >> "$LOG_FILE" 2>&1 || error_exit "rsyslog etkinleştirilemedi"
}

configure_rsyslog || error_exit "rsyslog yapılandırması başarısız"
log "rsyslog başarıyla yapılandırıldı"

# Tanılama fonksiyonları
diagnose_services() {
    log "Tanılama yapılıyor..."
    systemctl is-active --quiet auditd || { log "UYARI: auditd çalışmıyor"; systemctl start auditd; }
    systemctl is-active --quiet rsyslog || { log "UYARI: rsyslog çalışmıyor"; systemctl start rsyslog; }
    
    # Syslog testi
    logger "Setup scriptinden test mesajı" || log "UYARI: logger komutu başarısız"
    sleep 2
    grep -q "test mesajı" "$SYSLOG_FILE" 2>/dev/null && log "Syslog testi başarılı" || log "UYARI: Syslog testi başarısız"
    
    # Audit testi
    touch /etc/passwd || log "UYARI: Test touch başarısız"
    sleep 2
    ausearch -k passwd_modifications | grep -q "passwd" 2>/dev/null && log "Audit testi başarılı" || log "UYARI: Audit testi başarısız"
}

diagnose_services || log "UYARI: Tanılama sırasında sorunlar oluştu"
log "Kurulum tamamlandı. Ayrıntılar için $LOG_FILE kontrol edin"
exit 0
