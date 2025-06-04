#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------------------------  
# Auditd ve Rsyslog Yapılandırma Scripti (Eksik dosyaları otomatik kurar/oluşturur)
# - /etc/audit/auditd.conf dosyasını yedekler (değiştirmez).
# - Verilen audit kurallarını /etc/audit/rules.d/audit.rules dosyasına yazar.
# - audisp-syslog eklentisini /etc/audisp/plugins.d/syslog.conf içinde yapılandırır.
#   Eğer audisp-syslog yoksa, dağıtıma göre gerekli paketi kurmaya çalışır.
# - /etc/rsyslog.d/00-siem.conf ile omprog modülü aracılığıyla EXECVE kayıtlarını
#   concat_execve.py betiğine yönlendirir ve SIEM sunucusuna TCP üzerinden iletir.
# - concat_execve.py yoksa, basit bir placeholder Python betiği oluşturur.
# - Betik, adım adım hataları /var/log/setup_logging.log dosyasına kaydeder.
# ------------------------------------------------------------------------------ 
# SetupLogging v1

# Global Değişkenler
LOG_FILE="/var/log/setup_logging.log"
SYSLOG_CONF="/etc/rsyslog.d/00-siem.conf"
AUDITD_CONF="/etc/audit/auditd.conf"
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"
AUDISP_CONF="/etc/audisp/plugins.d/syslog.conf"
CONCAT_SCRIPT="/usr/local/bin/concat_execve.py"

# Kullanım Kontrolü
if [ "$#" -lt 2 ]; then
    echo "Kullanım: $0 <SIEM_IP> <SIEM_PORT>" >&2
    exit 1
fi

SIEM_IP="$1"
SIEM_PORT="$2"

# Log Dosyasını Oluştur ve İzin Ver
touch "$LOG_FILE" 2>/dev/null || { echo "ERROR: $LOG_FILE yazılamıyor." >&2; exit 1; }
chmod 640 "$LOG_FILE" 2>/dev/null || { echo "ERROR: $LOG_FILE izin ayarlanamadı." >&2; exit 1; }

# Zamanlı Log Fonksiyonu
log() {
    local mesaj ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    mesaj="$ts $1"
    echo "$mesaj" | tee -a "$LOG_FILE" >/dev/null 2>&1 || {
        echo "ERROR: Log dosyasına yazılamadı: $mesaj" >&2
        return 1
    }
}

# Hata Durumunda Çıkış ve Loglama
error_exit() {
    log "ERROR: $1"
    echo "ERROR: $1" >&2
    exit 1
}

# Root Kontrolü
if [ "$EUID" -ne 0 ]; then
    error_exit "Bu script root (sudo) ile çalıştırılmalı."
fi

log "=== Loglama yapılandırma scripti başlıyor ==="
log "SIEM IP: $SIEM_IP, SIEM Port: $SIEM_PORT"

# Dağıtım Tespiti
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
    VERSION_ID="$VERSION_ID"
else
    DISTRO="$(uname -s)"
    VERSION_ID="$(uname -r)"
fi

case "$DISTRO" in
    ubuntu|debian|kali)
        SYSLOG_FILE="/var/log/syslog"
        ;;
    rhel|centos|ol|oracle)
        SYSLOG_FILE="/var/log/messages"
        ;;
    *)
        error_exit "Desteklenmeyen dağıtım: $DISTRO"
        ;;
esac

log "Dağıtım: $DISTRO $VERSION_ID | Yerel syslog dosyası: $SYSLOG_FILE"

# -----------------------------------------------------------------------------
# 1) Gerekli Paketleri Kur (auditd, rsyslog, audisp plugin vs.)
# -----------------------------------------------------------------------------
install_packages() {
    log "Gerekli paketler kuruluyor..."
    case "$DISTRO" in
        ubuntu|debian|kali)
            apt-get update >> "$LOG_FILE" 2>&1 || error_exit "apt-get update başarısız."
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                auditd audispd-plugins rsyslog >> "$LOG_FILE" 2>&1 \
                || error_exit "Paket kurulumu (auditd, audispd-plugins, rsyslog) başarısız."
            ;;
        rhel|centos|ol|oracle)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y audit rsyslog audit-plugins >> "$LOG_FILE" 2>&1 \
                    || error_exit "dnf ile paket kurulumu başarısız."
            else
                yum install -y audit rsyslog audit-plugins >> "$LOG_FILE" 2>&1 \
                    || error_exit "yum ile paket kurulumu başarısız."
            fi
            ;;
    esac
    log "Paketler başarıyla kuruldu."
}

install_packages

# -----------------------------------------------------------------------------
# 2) auditd Yapılandırması
# -----------------------------------------------------------------------------
configure_auditd() {
    log "auditd yapılandırma adımları başlıyor..."

    # 2.1) auditd.conf Yedeği (Değiştirmiyoruz)
    if [ -f "$AUDITD_CONF" ]; then
        cp "$AUDITD_CONF" "${AUDITD_CONF}.bak" 2>/dev/null \
            || log "WARNING: $AUDITD_CONF yedeği oluşturulamadı."
        log "$AUDITD_CONF yedeklendi -> ${AUDITD_CONF}.bak"
    fi

    # 2.2) Kurallar Dizini ve Yedeği
    audit_dir="$(dirname "$AUDIT_RULES_FILE")"
    mkdir -p "$audit_dir" || error_exit "Audit kurallar dizini oluşturulamadı: $audit_dir"

    if [ -f "$AUDIT_RULES_FILE" ]; then
        cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.bak" 2>/dev/null \
            || log "WARNING: $AUDIT_RULES_FILE yedeği oluşturulamadı."
        log "$AUDIT_RULES_FILE yedeklendi -> ${AUDIT_RULES_FILE}.bak"
    fi

    # 2.3) Yeni Kuralları Yaz
    cat > "$AUDIT_RULES_FILE" << 'EOF' || error_exit "Audit kuralları dosyasına yazma başarısız."
## Tüm Mevcut Kuralları Sil
-D

## Buffer Boyutu
-b 8192

## Hata Modu: Panic
-f 1

## Hataları Yoksay
-i

##########################################
# [Self-Auditing]
##########################################
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools

# Audit loglarına erişim
-w /var/log/audit/ -k audit_log_access

##########################################
# Dosya Sistemi İzleme (Örnekler)
##########################################
-w /etc/passwd -p wa -k passwd_modifications
-w /etc/shadow -p wa -k passwd_modifications
-w /etc/group -p wa -k group_modifications
-w /etc/gshadow -p wa -k group_modifications
-w /etc/sudoers -p wa -k sudo_modifications
-w /etc/sudoers.d -p wa -k sudo_modifications

##########################################
# Komut Çalıştırma İzleme
##########################################
-a always,exit -F arch=b64 -F euid=0 -S execve -k root_command
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_command
-a always,exit -F arch=b64 -F euid>=1000 -S execve -k user_command
-a always,exit -F arch=b32 -S execve -F euid>=1000 -k user_command

##########################################
# Ağ Yapılandırma Değişiklikleri
##########################################
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-w /etc/hosts -p wa -k network_modifications
-w /etc/network/ -p wa -k network_modifications

##########################################
# Sistem Başlatma ve Kapatma
##########################################
-w /sbin/shutdown -p x -k system_state_modifications
-w /sbin/poweroff -p x -k system_state_modifications
-w /sbin/reboot -p x -k system_state_modifications
-w /sbin/halt -p x -k system_state_modifications

##########################################
# Kernel Modülü Yükleme
##########################################
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k kernel_modules
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k kernel_modules
-w /etc/modprobe.conf -p wa -k kernel_modules

##########################################
# Kimlik Doğrulama Olayları (PAM, vs.)
##########################################
-w /etc/pam.d/ -p wa -k pam_modifications
-w /var/log/faillog -p wa -k login_modifications
-w /var/log/lastlog -p wa -k login_modifications

##########################################
# Yetki Yükseltme İzleme
##########################################
-w /bin/su -p x -k su_execution
-w /usr/bin/sudo -p x -k sudo_execution

##########################################
# Şüpheli Aktiviteler
##########################################
-w /tmp -p x -k suspect_activity
-w /var/tmp -p x -k suspect_activity
-w /usr/bin/wget -p x -k suspect_activity
-w /usr/bin/curl -p x -k suspect_activity
-w /bin/nc -p x -k suspect_activity
-w /usr/bin/ssh -p x -k suspect_activity
-a always,exit -F arch=b64 -S ptrace -k suspect_activity
-a always,exit -F arch=b32 -S ptrace -k suspect_activity

##########################################
# Tüm Kullanıcı Komutları (Opsiyonel)
##########################################
-a always,exit -F arch=b64 -S execve -k user_commands
-a always,exit -F arch=b32 -S execve -k user_commands
EOF

    chmod 640 "$AUDIT_RULES_FILE" 2>/dev/null || error_exit "Audit kuralları dosyasına chmod 640 uygulanamadı."

    # 2.4) Kuralları Yükle (augenrules veya auditd restart)
    if command -v augenrules >/dev/null 2>&1; then
        log "augenrules bulundu; kurallar augenrules --load ile yüklenecek."
        if ! augenrules --load >> "$LOG_FILE" 2>&1; then
            log "WARNING: augenrules --load başarısız. auditd servisi restart edilecek."
            systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "auditd restart başarısız."
        fi
    else
        log "augenrules komutu yok; auditd servisi restart edilecek."
        systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "auditd restart başarısız."
    fi

    # 2.5) auditd servisini enable et
    systemctl enable auditd >> "$LOG_FILE" 2>&1 || error_exit "auditd enable yapılamadı."

    log "auditd yapılandırma adımları tamamlandı."
}

configure_auditd

# -----------------------------------------------------------------------------
# 3) audisp-syslog Yapılandırması (varsa; yoksa paket kurulumunu dener)
# -----------------------------------------------------------------------------
configure_audisp() {
    log "audisp-syslog yapılandırma adımları başlıyor..."

    # 3.1) audisp-syslog ikili dosyası arama
    if [ -f "/sbin/audisp-syslog" ]; then
        AUDISP_SYSLOG_PATH="/sbin/audisp-syslog"
    elif [ -f "/usr/sbin/audisp-syslog" ]; then
        AUDISP_SYSLOG_PATH="/usr/sbin/audisp-syslog"
    elif [ -f "/usr/lib/audisp/audisp-syslog" ]; then
        AUDISP_SYSLOG_PATH="/usr/lib/audisp/audisp-syslog"
    else
        log "WARNING: audisp-syslog ikili dosyası bulunamadı. Paket kurulacak..."
        # Eksikse paketi kurmaya çalış
        case "$DISTRO" in
            ubuntu|debian|kali)
                log "Ubuntu/Debian: audispd-plugins paketi kuruluyor..."
                apt-get update >> "$LOG_FILE" 2>&1 || log "WARNING: apt-get update başarısız."
                apt-get install -y audispd-plugins >> "$LOG_FILE" 2>&1 \
                    && log "audispd-plugins kuruldu." \
                    || log "WARNING: audispd-plugins kurulamadı."
                ;;
            rhel|centos|ol|oracle)
                log "RHEL/CentOS: audit-plugins paketi kuruluyor..."
                if command -v dnf >/dev/null 2>&1; then
                    dnf install -y audit-plugins >> "$LOG_FILE" 2>&1 \
                        && log "audit-plugins kuruldu." \
                        || log "WARNING: audit-plugins kurulamadı."
                else
                    yum install -y audit-plugins >> "$LOG_FILE" 2>&1 \
                        && log "audit-plugins kuruldu." \
                        || log "WARNING: audit-plugins kurulamadı."
                fi
                ;;
        esac

        # Kurulum sonrası tekrar kontrol et
        if [ -f "/sbin/audisp-syslog" ]; then
            AUDISP_SYSLOG_PATH="/sbin/audisp-syslog"
        elif [ -f "/usr/sbin/audisp-syslog" ]; then
            AUDISP_SYSLOG_PATH="/usr/sbin/audisp-syslog"
        elif [ -f "/usr/lib/audisp/audisp-syslog" ]; then
            AUDISP_SYSLOG_PATH="/usr/lib/audisp/audisp-syslog"
        else
            log "WARNING: audisp-syslog hâlâ bulunamadı; devam ediliyor (uyarıyla)."
            AUDISP_SYSLOG_PATH=""
        fi
    fi

    # 3.2) audisp dizinini oluştur
    audisp_dir="$(dirname "$AUDISP_CONF")"
    mkdir -p "$audisp_dir" || error_exit "audisp config dizini oluşturulamadı: $audisp_dir"

    # 3.3) Mevcut varsa yedeğini al
    if [ -f "$AUDISP_CONF" ]; then
        cp "$AUDISP_CONF" "${AUDISP_CONF}.bak" 2>/dev/null \
            || log "WARNING: $AUDISP_CONF yedeği oluşturulamadı."
        log "$AUDISP_CONF yedeklendi -> ${AUDISP_CONF}.bak"
    fi

    # 3.4) Konfigürasyonu yaz (path boş ise, comment satırı ekle)
    if [ -n "$AUDISP_SYSLOG_PATH" ]; then
        cat > "$AUDISP_CONF" << EOF || error_exit "audisp config yazılamadı."
active = yes
direction = out
path = $AUDISP_SYSLOG_PATH
type = always
args = LOG_LOCAL3
format = string
EOF
        log "audisp-syslog config yazıldı: path = $AUDISP_SYSLOG_PATH"
    else
        cat > "$AUDISP_CONF" << EOF || error_exit "audisp config yazılamadı."
# audisp-syslog ikili dosyası bulunamadı; plugin devre dışı bırakıldı.
active = no
direction = out
path = 
type = always
args = LOG_LOCAL3
format = string
EOF
        log "WARNING: audisp-syslog bulunamadığı için plugin devre dışı bırakıldı."
    fi

    chmod 640 "$AUDISP_CONF" 2>/dev/null || error_exit "audisp config chmod 640 yapılamadı."
    log "audisp yapılandırma adımları tamamlandı."
}

configure_audisp

# -----------------------------------------------------------------------------
# 4) concat_execve.py Dosyasını Kontrol Et, Yoksa Oluştur
# -----------------------------------------------------------------------------
check_or_create_concat_script() {
    log "concat_execve.py varlığı kontrol ediliyor..."
    if [ ! -f "$CONCAT_SCRIPT" ]; then
        log "concat_execve.py bulunamadı. Basit placeholder oluşturuluyor..."
        cat > "$CONCAT_SCRIPT" << 'EOF' || error_exit "concat_execve.py oluşturulamadı."
#!/usr/bin/env python3
import sys

"""
Bu basit placeholder betiği, STDIN'den aldığı her satırı (syslog) 
STDOUT'a (rsyslog) olduğu gibi döndürür. 
Kendi ortamınıza uygun şekilde EXECVE mesajından a0 alanı oluşturma 
mantığını buraya ekleyebilirsiniz.
"""
for line in sys.stdin:
    # Burada “line” zaten tam formattaki syslog satırıdır.
    # İhtiyacınıza göre ayrıştırıp a0 alanını oluşturabilirsiniz.
    sys.stdout.write(line)
EOF
        chmod +x "$CONCAT_SCRIPT" || error_exit "concat_execve.py chmod +x yapılamadı."
        log "concat_execve.py placeholder oluşturuldu ve çalıştırma izni verildi."
    else
        chmod +x "$CONCAT_SCRIPT" 2>/dev/null || error_exit "concat_execve.py chmod +x yapılamadı."
        log "concat_execve.py zaten mevcut; chmod +x uygulandı."
    fi
}

check_or_create_concat_script

# -----------------------------------------------------------------------------
# 5) rsyslog Yapılandırması
# -----------------------------------------------------------------------------
configure_rsyslog() {
    log "rsyslog yapılandırma adımları başlıyor..."

    # 5.1) Mevcut konfig yedeği
    if [ -f "$SYSLOG_CONF" ]; then
        cp "$SYSLOG_CONF" "${SYSLOG_CONF}.bak" 2>/dev/null \
            || log "WARNING: $SYSLOG_CONF yedeği oluşturulamadı."
        log "$SYSLOG_CONF yedeklendi -> ${SYSLOG_CONF}.bak"
    fi

    # 5.2) Yeni konfig’u yaz (değişken genişlemesi için << EOF kullan.)
    cat > "$SYSLOG_CONF" << EOF || error_exit "rsyslog config yazılamadı."
module(load="omprog")

# Kernel facility'si altındaki mesajları durdur
if \$syslogfacility-text == "kern" then {
    stop
}

# Daemon facility'si altındaki mesajları durdur
if \$syslogfacility-text == "daemon" then {
    stop
}

# local3 facility'si altından, içinde "type=EXECVE" geçenleri işleme al
if \$syslogfacility-text == "local3" and \$msg contains "type=EXECVE" then {
    action(
        type="omprog"
        binary="$CONCAT_SCRIPT"
        useTransactions="on"
        name="execve_transformer"
    )
    # Dönüştürülen logu SIEM sunucusuna TCP ile ilet
    action(
        type="omfwd"
        target="$SIEM_IP"
        port="$SIEM_PORT"
        protocol="tcp"
    )
    stop
}
EOF

    # 5.3) rsyslog servisini yeniden başlat ve enable et
    systemctl restart rsyslog >> "$LOG_FILE" 2>&1 || error_exit "rsyslog servisi restart edilemedi."
    systemctl enable rsyslog >> "$LOG_FILE" 2>&1 || error_exit "rsyslog enable yapılamadı."

    log "rsyslog yapılandırma adımları tamamlandı."
}

configure_rsyslog

# -----------------------------------------------------------------------------
# 6) Servisleri Denetle ve Basit Test Yap
# -----------------------------------------------------------------------------
diagnose_services() {
    log "Servis denetimleri yapılıyor..."

    # 6.1) auditd durumu
    if ! systemctl is-active --quiet auditd; then
        log "WARNING: auditd çalışmıyor. Başlatılıyor..."
        systemctl start auditd || log "ERROR: auditd başlatılamadı."
    fi

    # 6.2) rsyslog durumu
    if ! systemctl is-active --quiet rsyslog; then
        log "WARNING: rsyslog çalışmıyor. Başlatılıyor..."
        systemctl start rsyslog || log "ERROR: rsyslog başlatılamadı."
    fi

    # 6.3) Syslog testi (local3 facility ile örnek mesaj)
    test_msg="SIEM Test Mesajı $(date '+%s')"
    logger -p local3.info "$test_msg" || log "WARNING: logger komutu başarısız."
    sleep 2
    if grep -q "$test_msg" "$SYSLOG_FILE"; then
        log "Syslog testi başarılı: \"$test_msg\" bulundu."
    else
        log "WARNING: Syslog testi başarısız: \"$test_msg\" bulunamadı."
    fi

    # 6.4) Audit testi (passwd_modifications anahtar kelimesiyle)
    touch /etc/passwd || log "WARNING: /etc/passwd dokunma testi başarısız."
    sleep 2
    if ausearch -k passwd_modifications | grep -q "passwd"; then
        log "Audit testi başarılı: passwd_modifications kaydı bulundu."
    else
        log "WARNING: Audit testi başarısız: passwd_modifications kaydı bulunamadı."
    fi
}

diagnose_services

log "=== Kurulum ve yapılandırma tamamlandı. Detaylar için: $LOG_FILE ==="
exit 0
