#!/usr/bin/env bash

# setup_logging.sh
# Bu script, auditd ve rsyslog yapılandırmasını yapar, logları SIEM'e iletir ve doğrular.
# Desteklenen dağıtımlar: Debian/Ubuntu/Kali, Red Hat/CentOS, Oracle Linux
# Kullanım: sudo bash setup_logging.sh <SIEM_IP> <SIEM_PORT>

set -e

# Değişkenler
SIEM_IP="$1"
SIEM_PORT="$2"
LOG_FILE="/var/log/setup_logging.sh.log"
SYSLOG_FILE=""
AUDITD_LOG_FILE="/var/log/audit/audit.log"

# Audit kurallarını tanımlama
AUDIT_RULES_CONTENT=$(cat <<'EOF'
## Mevcut tüm kuralları sil
-D

## Buffer Boyutu
-b 8192

## Hata Modu
-f 1

## Hataları yoksayma (Genellikle önerilmez, ancak orijinal script'te vardı)
# -i

##########################################
# [Kendi Kendini Denetleme]
##########################################
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools

# Audit loglarına erişim
-w /var/log/audit/ -p rwa -k audit_log_access

##########################################
# Dosya Sistemi İzleme (Örnekler)
##########################################
-w /etc/passwd -p wa -k file_passwd_changes
-w /etc/shadow -p wa -k file_shadow_changes
-w /etc/group -p wa -k file_group_changes
-w /etc/gshadow -p wa -k file_gshadow_changes
-w /etc/sudoers -p wa -k file_sudoers_changes
-w /etc/sudoers.d/ -p wa -k file_sudoers_d_changes

##########################################
# İşlem Yürütme İzleme
##########################################
# Kök kullanıcı (euid=0) tarafından yürütülen komutlar
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_execve
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_execve

# Giriş yapmış kullanıcılar (auid>=1000 ve auid tanımsız değil) tarafından yürütülen komutlar
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k user_execve
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k user_execve

##########################################
# Ağ Konfigürasyon Değişiklikleri
##########################################
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k net_config_changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k net_config_changes
-w /etc/hosts -p wa -k net_hosts_file_changes
-w /etc/network/ -p wa -k deb_net_interfaces_changes # Debian/Ubuntu specific path
-w /etc/sysconfig/network-scripts/ -p wa -k rhel_net_scripts_changes # RHEL/CentOS specific path
-w /etc/netplan/ -p wa -k ubuntu_netplan_changes # Ubuntu Netplan

##########################################
# Sistem Başlatma ve Kapatma
##########################################
-w /sbin/shutdown -p x -k sys_shutdown
-w /sbin/poweroff -p x -k sys_poweroff
-w /sbin/reboot -p x -k sys_reboot
-w /sbin/halt -p x -k sys_halt

##########################################
# Çekirdek Modül Yükleme
##########################################
-a always,exit -F path=/sbin/insmod -F perm=x -F auid>=1000 -F auid!=-1 -k mod_insmod
-a always,exit -F path=/sbin/rmmod -F perm=x -F auid>=1000 -F auid!=-1 -k mod_rmmod
-a always,exit -F path=/sbin/modprobe -F perm=x -F auid>=1000 -F auid!=-1 -k mod_modprobe
-w /etc/modprobe.conf -p wa -k mod_conf_changes
-w /etc/modprobe.d/ -p wa -k mod_conf_d_changes

##########################################
# Kimlik Doğrulama Olayları (PAM vb.)
##########################################
-w /etc/pam.d/ -p wa -k auth_pam_changes
-w /var/log/faillog -p wa -k auth_faillog_access
-w /var/log/lastlog -p wa -k auth_lastlog_access
-w /etc/login.defs -p wa -k auth_login_defs_changes
-w /etc/security/opasswd -p wa -k auth_opasswd_changes


##########################################
# Yetki Yükseltme
##########################################
-w /bin/su -p x -k priv_su_exec
-w /usr/bin/sudo -p x -k priv_sudo_exec
-a always,exit -F arch=b64 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k priv_escalation_syscalls
-a always,exit -F arch=b32 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k priv_escalation_syscalls

##########################################
# Şüpheli Aktiviteler (Örnekler)
##########################################
# -w /tmp -p x -k suspect_activity_tmp_exec # Genellikle çok fazla log üretir
# -w /var/tmp -p x -k suspect_activity_vartmp_exec # Genellikle çok fazla log üretir
-w /usr/bin/wget -p x -k susp_wget
-w /usr/bin/curl -p x -k susp_curl
-w /bin/nc -p x -k susp_netcat
-w /usr/bin/ncat -p x -k susp_ncat
-w /usr/bin/ssh -p x -k susp_ssh
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k susp_ptrace_read
-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k susp_ptrace_read

## Kuralları kalıcı yap (isteğe bağlı, en sona eklenmeli)
# -e 2
EOF
)

# Fonksiyonlar
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}

error_exit() {
    log "HATA: $1"
    exit 1
}

# Diagnostic Fonksiyonları
diagnose_rsyslog() {
    log "----- RSYSLOG Diagnostic -----"
    if ! systemctl is-active --quiet rsyslog; then
        log "Rsyslog servisi aktif değil. Başlatılıyor."
        systemctl start rsyslog &>> "$LOG_FILE" || log "HATA: Rsyslog servisi başlatılamadı."
        log "Rsyslog servisi başlatıldı."
    else
        log "Rsyslog servisi aktif."
    fi

    if rsyslogd -N1 &>> "$LOG_FILE"; then
        log "Rsyslog konfigürasyon doğrulandı."
    else
        log "UYARI: Rsyslog konfigürasyonunda hata olabilir. Düzeltme deneniyor."
        fix_rsyslog_config
    fi

    if [ -f "$SYSLOG_FILE" ]; then log "$SYSLOG_FILE dosyası mevcut."; else log "HATA: $SYSLOG_FILE dosyası bulunamadı."; fi
    if grep -q "local1.* @@${SIEM_IP}:${SIEM_PORT}" /etc/rsyslog.d/60-qradar.conf &>/dev/null || \
       grep -q "local1.* @@${SIEM_IP}:${SIEM_PORT}" /etc/rsyslog.d/60-siem.conf &>/dev/null; then # Original used 60-siem.conf
        log "Rsyslog SIEM konfigürasyonu doğru görünüyor."
    else
        log "HATA: SIEM konfigürasyonu /etc/rsyslog.d/60-qradar.conf (veya 60-siem.conf) dosyasında bulunamadı veya hatalı."
        fix_rsyslog_config
    fi
    log "----- RSYSLOG Diagnostic Bitti -----"
}

diagnose_auditd() {
    log "----- AUDITD Diagnostic -----"
    if ! systemctl is-active --quiet auditd; then
        log "Auditd servisi aktif değil. Başlatılıyor."
        systemctl start auditd &>> "$LOG_FILE" || log "HATA: Auditd servisi başlatılamadı."
        log "Auditd servisi başlatıldı."
    else
        log "Auditd servisi aktif."
    fi

    if grep -i "error" "$AUDITD_LOG_FILE" &>> "$LOG_FILE"; then
        log "UYARI: Auditd loglarında 'error' bulundu. Detaylar için $AUDITD_LOG_FILE kontrol edin."
    else
        log "Auditd loglarında 'error' bulunamadı."
    fi

    if auditctl -l | grep -q "user_execve"; then # Updated key
        log "Audit 'user_execve' kuralları yüklendi."
    else
        log "UYARI: Audit 'user_execve' kuralları yüklenmemiş olabilir. Düzeltme deneniyor."
        fix_audisp_syslog_config # This also reloads rules
    fi
    log "----- AUDITD Diagnostic Bitti -----"
}

diagnose_permissions() {
    log "----- Permissions Diagnostic -----"
    if [ -f "$SYSLOG_FILE" ]; then
        ls -l "$SYSLOG_FILE" &>> "$LOG_FILE"
        if [ ! -r "$SYSLOG_FILE" ]; then # Check if readable by script for grep, though rsyslog needs write
            log "UYARI: $SYSLOG_FILE okuma izni yok (script için)."
        fi
        # Rsyslog'un yazma iznini doğrudan test etmek karmaşık, servis loglarına bakılmalı.
    else
        log "HATA: $SYSLOG_FILE dosyası bulunamadı."
    fi
    log "----- Permissions Diagnostic Bitti -----"
}

diagnose_selinux_apparmor() {
    log "----- SELinux/AppArmor Diagnostic -----"
    if command -v getenforce &>/dev/null; then
        SELINUX_STATUS=$(getenforce)
        log "SELinux durumu: $SELINUX_STATUS"
        if [ "$SELINUX_STATUS" = "Enforcing" ]; then
            log "SELinux Enforcing modunda. Log iletimi için policy izinlerini kontrol edin (örn: auditallow, semanage)."
            log "Rsyslog için: 'getsebool -a | grep syslog' ve 'setsebool -P syslogd_can_network_connect on'"
            log "Auditd için genellikle sorun olmaz ama AVC deny loglarını kontrol edin: 'ausearch -m avc -ts recent'"
        fi
    else
        log "SELinux (getenforce) komutu bulunamadı."
    fi

    if command -v aa-status &>/dev/null; then
        if aa-status --enabled &>/dev/null; then
            log "AppArmor etkin. Rsyslog ve Auditd profillerini kontrol edin. (örn: /etc/apparmor.d/)"
        else
            log "AppArmor etkin değil."
        fi
    else
        log "AppArmor (aa-status) komutu bulunamadı."
    fi
    log "----- SELinux/AppArmor Diagnostic Bitti -----"
}

fix_rsyslog_config() {
    log "Rsyslog konfigürasyonunu düzeltmeye çalışıyor (/etc/rsyslog.d/60-qradar.conf)."
    # README /etc/rsyslog.d/60-qradar.conf kullanıyor, script 60-siem.conf. QRadar için 60-qradar.conf daha uygun.
    cat <<EOF > /etc/rsyslog.d/60-qradar.conf
# Forward local1.* to QRadar SIEM
local1.* @@${SIEM_IP}:${SIEM_PORT}
EOF
    log "Rsyslog /etc/rsyslog.d/60-qradar.conf oluşturuldu/güncellendi."
    systemctl restart rsyslog &>> "$LOG_FILE" || log "HATA: Rsyslog servisi yeniden başlatılamadı (düzeltme sonrası)."
    if rsyslogd -N1 &>> "$LOG_FILE"; then log "Rsyslog konfigürasyonu düzeltme sonrası doğrulandı."; else log "HATA: Rsyslog konfigürasyonu düzeltme sonrası hala hatalı."; fi
}

fix_audisp_syslog_config() {
    log "Audisp-syslog plugin konfigürasyonunu düzeltmeye çalışıyor."
    local audisp_syslog_conf_file="/etc/audit/plugins.d/syslog.conf"
    # audisp-syslog binary yolu kontrolü
    local audisp_syslog_path=""
    if [ -x "/sbin/audisp-syslog" ]; then # Genellikle RHEL tabanlı sistemlerde /sbin
        audisp_syslog_path="/sbin/audisp-syslog"
    elif [ -x "/usr/sbin/audisp-syslog" ]; then # Genellikle Debian tabanlı sistemlerde /usr/sbin
        audisp_syslog_path="/usr/sbin/audisp-syslog"
    else
        log "HATA: audisp-syslog çalıştırılabilir dosyası /sbin veya /usr/sbin içinde bulunamadı."
        return 1
    fi
    log "Kullanılacak audisp-syslog yolu: $audisp_syslog_path"

    cat <<EOF > "$audisp_syslog_conf_file"
active = yes
direction = out
path = $audisp_syslog_path
type = always
args = LOG_LOCAL1
format = string
EOF
    chmod 640 "$audisp_syslog_conf_file" &>> "$LOG_FILE" || log "UYARI: $audisp_syslog_conf_file izinleri ayarlanamadı."
    log "Audisp plugin $audisp_syslog_conf_file oluşturuldu/güncellendi."

    systemctl restart auditd &>> "$LOG_FILE" || log "HATA: Auditd servisi yeniden başlatılamadı (düzeltme sonrası)."
    log "Auditd servisi yeniden başlatıldı (düzeltme sonrası)."
    # Kuralları yeniden yükle
    if command -v augenrules &>/dev/null; then
        augenrules --load &>> "$LOG_FILE" || log "HATA: Audit kuralları augenrules ile yüklenemedi (düzeltme sonrası)."
    else
        auditctl -R "/etc/audit/rules.d/audit.rules" &>> "$LOG_FILE" || log "HATA: Audit kuralları auditctl ile yüklenemedi (düzeltme sonrası)."
    fi
    log "Audit kuralları yeniden yüklendi (düzeltme sonrası)."
}

# Root yetkisi kontrolü
if [ "$EUID" -ne 0 ]; then
    echo "Lütfen script'i root yetkisiyle çalıştırın."
    exit 1
fi

# Argüman kontrolü
if [ -z "$SIEM_IP" ] || [ -z "$SIEM_PORT" ]; then
    echo "Kullanım: $0 <SIEM_IP_ADRESI> <SIEM_PORTU>"
    echo "Örnek: sudo bash $0 192.168.1.100 514"
    exit 1
fi

# Log dosyasını oluştur ve izinlerini ayarla
touch "$LOG_FILE" &>/dev/null || { echo "HATA: Log dosyası ($LOG_FILE) oluşturulamıyor." >&2; exit 1; }
chmod 640 "$LOG_FILE" &>/dev/null || { echo "HATA: Log dosyası ($LOG_FILE) izinleri ayarlanamıyor." >&2; exit 1; }

log "=== Loglama yapılandırma scripti başlıyor ==="
log "SIEM IP: $SIEM_IP, Port: $SIEM_PORT"

# Dağıtım tespiti
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO=$ID
    VERSION_ID_NUM=$VERSION_ID # Sadece numara kısmı için
else
    DISTRO=$(uname -s)
    VERSION_ID_NUM=$(uname -r)
fi
log "Dağıtım: $DISTRO, Versiyon: $VERSION_ID_NUM"

# Syslog dosyasını belirleme (testler için)
case "$DISTRO" in
    ubuntu|debian|kali) SYSLOG_FILE="/var/log/syslog";;
    rhel|centos|oracle|almalinux|rocky) SYSLOG_FILE="/var/log/messages";;
    *) error_exit "Bu script şu an sadece Debian/Ubuntu/Kali, Red Hat/CentOS/Oracle ve türevleri için desteklenmektedir.";;
esac
log "Yerel sistem log dosyası (testler için): $SYSLOG_FILE"

# Paket kurulum fonksiyonu
install_packages() {
    log "Gerekli paketler kuruluyor: auditd, audispd-plugins (Debian/Ubuntu) veya audit (RHEL), rsyslog"
    case "$DISTRO" in
        ubuntu|debian|kali)
            apt-get update -y >> "$LOG_FILE" 2>&1 || error_exit "'apt-get update' başarısız oldu."
            apt-get install -y auditd audispd-plugins rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Paket kurulumu (apt-get) başarısız."
            ;;
        rhel|centos|oracle|almalinux|rocky)
            if command -v dnf &>/dev/null; then
                dnf install -y audit rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Paket kurulumu (dnf) başarısız."
            else
                yum install -y audit rsyslog >> "$LOG_FILE" 2>&1 || error_exit "Paket kurulumu (yum) başarısız."
            fi
            ;;
    esac
    log "Paketler başarıyla kuruldu."
}

install_packages

log "Auditd servisi başlatılıyor ve etkinleştiriliyor."
systemctl enable auditd >> "$LOG_FILE" 2>&1 || error_exit "auditd servisi etkinleştirilemedi."
systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "auditd servisi başlatılamadı/yeniden başlatılamadı."
log "auditd servisi başarıyla başlatıldı ve etkinleştirildi."

# Audisp-syslog plugin yapılandırması
AUDISP_SYSLOG_CONF_FILE="/etc/audit/plugins.d/syslog.conf"
AUDISP_SYSLOG_PATH=""
# Audisp-syslog binary yolu tespiti (daha güvenilir)
if [ -x "/sbin/audisp-syslog" ]; then AUDISP_SYSLOG_PATH="/sbin/audisp-syslog"; fi
if [ -z "$AUDISP_SYSLOG_PATH" ] && [ -x "/usr/sbin/audisp-syslog" ]; then AUDISP_SYSLOG_PATH="/usr/sbin/audisp-syslog"; fi

if [ -z "$AUDISP_SYSLOG_PATH" ]; then
    error_exit "audisp-syslog çalıştırılabilir dosyası bulunamadı."
fi
log "Kullanılacak audisp-syslog yolu: $AUDISP_SYSLOG_PATH"

mkdir -p "$(dirname "$AUDISP_SYSLOG_CONF_FILE")" || error_exit "$AUDISP_SYSLOG_CONF_FILE dizini oluşturulamadı."
cat <<EOF > "$AUDISP_SYSLOG_CONF_FILE"
active = yes
direction = out
path = $AUDISP_SYSLOG_PATH
type = always
args = LOG_LOCAL1
format = string
EOF
chmod 640 "$AUDISP_SYSLOG_CONF_FILE" >> "$LOG_FILE" 2>&1 || log "UYARI: $AUDISP_SYSLOG_CONF_FILE izinleri ayarlanamadı."
log "Audisp syslog plugin ayarları yapıldı: $AUDISP_SYSLOG_CONF_FILE -> LOG_LOCAL1"

# Auditd'yi yeniden başlat (audisp plugin değişiklikleri için)
systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "auditd servisi audisp ayarları sonrası yeniden başlatılamadı."
log "auditd servisi audisp ayarları sonrası yeniden başlatıldı."

# Rsyslog konfigürasyonu - SIEM'e log iletimi (QRadar için)
RSYSLOG_QRADAR_CONF="/etc/rsyslog.d/60-qradar.conf" # README.md ile uyumlu dosya adı
mkdir -p "$(dirname "$RSYSLOG_QRADAR_CONF")" || error_exit "$RSYSLOG_QRADAR_CONF dizini oluşturulamadı."
cat <<EOF > "$RSYSLOG_QRADAR_CONF"
# Forward local1.* (audit logs) to QRadar SIEM
local1.* @@${SIEM_IP}:${SIEM_PORT}
EOF
log "Rsyslog konfigürasyonu oluşturuldu: $RSYSLOG_QRADAR_CONF (local1.* -> ${SIEM_IP}:${SIEM_PORT})"

# Rsyslog'u yeniden başlat
systemctl enable rsyslog >> "$LOG_FILE" 2>&1 || log "UYARI: rsyslog servisi etkinleştirilemedi."
systemctl restart rsyslog >> "$LOG_FILE" 2>&1 || error_exit "rsyslog servisi yeniden başlatılamadı."
log "rsyslog servisi yeniden başlatıldı ve etkinleştirildi."

# Audit kurallarını ekleme
AUDIT_RULES_D_DIR="/etc/audit/rules.d"
CUSTOM_AUDIT_RULES_FILE="$AUDIT_RULES_D_DIR/99-custom-audit.rules" # rules.d içine koymak daha iyi bir pratik
mkdir -p "$AUDIT_RULES_D_DIR" || error_exit "$AUDIT_RULES_D_DIR oluşturulamadı."

log "Audit kuralları dosyası oluşturuluyor: $CUSTOM_AUDIT_RULES_FILE"
echo "$AUDIT_RULES_CONTENT" > "$CUSTOM_AUDIT_RULES_FILE" || error_exit "$CUSTOM_AUDIT_RULES_FILE yazılamadı."
chmod 640 "$CUSTOM_AUDIT_RULES_FILE" || error_exit "$CUSTOM_AUDIT_RULES_FILE izinleri ayarlanamadı."
log "Audit kuralları dosyası oluşturuldu: $CUSTOM_AUDIT_RULES_FILE"

# Audit kurallarını yükle
log "Audit kuralları yükleniyor..."
if command -v augenrules &>/dev/null; then
    augenrules --load >> "$LOG_FILE" 2>&1 || error_exit "Audit kuralları 'augenrules --load' ile yüklenemedi."
else
    # Fallback to auditctl if augenrules is not present (less common for persistent rules)
    log "augenrules komutu bulunamadı, auditctl -R ile yükleme denenecek (bu kalıcı olmayabilir, /etc/audit/audit.rules doğrudan düzenlenmeli veya augenrules kurulmalı)."
    auditctl -R "$CUSTOM_AUDIT_RULES_FILE" >> "$LOG_FILE" 2>&1 || error_exit "Audit kuralları 'auditctl -R' ile yüklenemedi."
fi
log "Audit kuralları başarıyla yüklendi."

# Auditd'yi yeniden başlat (kurallar yüklendikten sonra emin olmak için)
systemctl restart auditd >> "$LOG_FILE" 2>&1 || error_exit "auditd servisi kurallar yüklendikten sonra yeniden başlatılamadı."
log "auditd servisi kurallar yüklendikten sonra yeniden başlatıldı."

# Testler
log "--- Testler Başlatılıyor ---"
# Test 1: Local syslog test
TEST_MSG_SYSLOG="Test syslog message from setup_logging.sh $(date)"
log "Test mesajı '$TEST_MSG_SYSLOG' yerel syslog'a (local1.info üzerinden) gönderiliyor..."
logger -p local1.info "$TEST_MSG_SYSLOG"
sleep 3
if grep -Fq "$TEST_MSG_SYSLOG" "$SYSLOG_FILE"; then
    log "Test 1 BAŞARILI: Syslog test mesajı '$SYSLOG_FILE' içinde bulundu."
else
    log "Test 1 BAŞARISIZ veya GECİKMELİ: Syslog test mesajı '$SYSLOG_FILE' içinde bulunamadı. Diagnostik çalıştırılıyor..."
    diagnose_rsyslog
    logger -p local1.info "$TEST_MSG_SYSLOG" # Retry
    sleep 3
    if grep -Fq "$TEST_MSG_SYSLOG" "$SYSLOG_FILE"; then
         log "Test 1 BAŞARILI (tekrar deneme sonrası)."
    else
         log "Test 1 BAŞARISIZ (tekrar deneme sonrası). Lütfen rsyslog ve audisp-syslog yapılandırmasını manuel kontrol edin."
    fi
fi

# Test 2: Audit log testi (/etc/passwd değişikliği)
AUDIT_TEST_KEY="file_passwd_changes"
log "/etc/passwd dosyasına dokunularak '$AUDIT_TEST_KEY' için audit log testi yapılıyor."
touch /etc/passwd || log "UYARI: 'touch /etc/passwd' komutu başarısız oldu."
sleep 3 # Audit sisteminin logu işlemesi için zaman tanıyın

log "ausearch ile '$AUDIT_TEST_KEY' anahtarı için son audit logları kontrol ediliyor..."
if ausearch -k "$AUDIT_TEST_KEY" --raw --start today | grep -q 'type=SYSCALL.*key="file_passwd_changes"'; then
    log "Test 2 ADIM 1 BAŞARILI: '$AUDIT_TEST_KEY' audit logu ausearch ile bulundu."

    log "'$AUDIT_TEST_KEY' logunun '$SYSLOG_FILE' dosyasına (local1 üzerinden) iletilip iletilmediği kontrol ediliyor..."
    if grep -Fq "$AUDIT_TEST_KEY" "$SYSLOG_FILE"; then
        log "Test 2 ADIM 2 BAŞARILI: '$AUDIT_TEST_KEY' audit logu '$SYSLOG_FILE' içinde bulundu."
    else
        log "Test 2 ADIM 2 BAŞARISIZ veya GECİKMELİ: '$AUDIT_TEST_KEY' audit logu '$SYSLOG_FILE' içinde bulunamadı. Diagnostik çalıştırılıyor..."
        diagnose_auditd # Bu audisp ve auditd'yi kontrol eder/düzeltir
        diagnose_rsyslog
        touch /etc/passwd # Retry event
        sleep 3
        if grep -Fq "$AUDIT_TEST_KEY" "$SYSLOG_FILE"; then
            log "Test 2 ADIM 2 BAŞARILI (tekrar deneme sonrası)."
        else
            log "Test 2 ADIM 2 BAŞARISIZ (tekrar deneme sonrası). Lütfen auditd, audisp-syslog ve rsyslog yapılandırmasını manuel kontrol edin."
        fi
    fi
else
    log "Test 2 ADIM 1 BAŞARISIZ: '$AUDIT_TEST_KEY' audit logu ausearch ile bulunamadı. Diagnostik çalıştırılıyor..."
    diagnose_auditd
    touch /etc/passwd # Retry event
    sleep 3
     if ausearch -k "$AUDIT_TEST_KEY" --raw --start today | grep -q 'type=SYSCALL.*key="file_passwd_changes"'; then
        log "Test 2 ADIM 1 BAŞARILI (tekrar deneme sonrası)."
        # Adım 2'yi burada tekrarla...
     else
        log "Test 2 ADIM 1 BAŞARISIZ (tekrar deneme sonrası). Lütfen audit kurallarını ve auditd servisini manuel kontrol edin."
     fi
fi
log "--- Testler Bitti ---"

# Son diagnostikler
diagnose_permissions
diagnose_selinux_apparmor

log "Doğrulama: Audit loglarının SIEM'e iletilip iletilmediğini kontrol etmek için SIEM sunucusunda tcpdump kullanabilirsiniz."
log "Örnek komut (SIEM sunucusunda değil, log gönderen bu makinede çalıştırılabilir):"
log "sudo tcpdump -i any host $SIEM_IP and port $SIEM_PORT -A -n"
log "Veya SIEM arayüzünden logları kontrol edin."

log "=== Loglama yapılandırma scripti tamamlandı ==="
exit 0
