#!/usr/bin/env bash
#
# unified_log_forwarding_setup.sh
#
# Bu betik, auditd ve rsyslog’u otomatik olarak yapılandırarak:
#   - Gerekli paketleri (auditd, audispd-plugins, rsyslog, python3) kurar.
#   - EXECVE argümanlarını birleştiren bir Python script’i konuşlandırır.
#   - Kapsamlı audit kurallarını /etc/audit/rules.d altında tanımlar.
#   - audispd-plugins aracılığıyla audit kayıtlarını rsyslog'un local3 facility'sine gönderir (eğer possible).
#   - Rsyslog’u yalnızca saldırı tespiti için gerekli audit kayıtlarını QRadar SIEM’e TCP ile iletecek şekilde yapılandırır.
#   - (RHEL ailesi için) SELinux ve Firewalld ayarlarını düzenler.
#
# Kullanım: sudo bash unified_log_forwarding_setup.sh <SIEM_IP> <SIEM_PORT>
#

set -euo pipefail

# --- Konfigürasyon Değişkenleri ---
LOG_FILE="/var/log/unified_log_setup.log"
PYTHON_SCRIPT_PATH="/usr/local/bin/concat_execve_args.py"
AUDIT_RULES_D_DIR="/etc/audit/rules.d"
AUDIT_RULES_FILE="$AUDIT_RULES_D_DIR/99-unified-audit-rules.conf"
AUDISP_PLUGIN_CONF_FILE="/etc/audisp/plugins.d/syslog.conf"
RSYSLOG_SIEM_CONF="/etc/rsyslog.d/01-unified-siem.conf"

AUDIT_FACILITY="local3"  # Syslog facility olarak kullanacağımız audit facility

# --- Yardımcı Fonksiyonlar ---
log() {
    local message
    message="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$message" | tee -a "$LOG_FILE" >&2
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

# --- Ön Koşul Kontrolleri ---
if [ "$EUID" -ne 0 ]; then
    error_exit "Bu betik root olarak çalıştırılmalıdır. Lütfen sudo kullanın."
fi

if [ $# -lt 2 ]; then
    echo "Usage: $0 <SIEM_IP> <SIEM_PORT>" >&2
    log "Kullanım hatası: $0 <SIEM_IP> <SIEM_PORT>"
    exit 1
fi

SIEM_IP="$1"
SIEM_PORT="$2"

# Log dosyasını başlat
touch "$LOG_FILE" &>/dev/null || { echo "FATAL: $LOG_FILE oluşturulamadı." >&2; exit 1; }
chmod 640 "$LOG_FILE" &>/dev/null || { echo "FATAL: $LOG_FILE üzerinde izin ayarlanamadı." >&2; exit 1; }

log "=== Unified Log Forwarding Kurulum Betiği Başlıyor ==="
log "SIEM IP: $SIEM_IP, Port: $SIEM_PORT"

# --- Dağıtım (Distribution) Tespiti ---
DISTRO=""
DISTRO_FAMILY=""   # debian_family veya rhel_family
VERSION_ID_NUM=""
LOCAL_SYSLOG_FILE_FOR_TESTS=""

if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO="$ID"
    VERSION_ID_NUM="$VERSION_ID"
    # Debian tabanlı mı diye kontrol
    if echo "$ID_LIKE" | grep -qi "debian" || echo "$ID" | grep -Eq "^(debian|ubuntu|kali)$"; then
        DISTRO_FAMILY="debian_family"
        LOCAL_SYSLOG_FILE_FOR_TESTS="/var/log/syslog"
    # RHEL tabanlı mı diye kontrol
    elif echo "$ID_LIKE" | grep -qi "rhel" || echo "$ID_LIKE" | grep -qi "fedora" || echo "$ID" | grep -Eq "^(rhel|centos|almalinux|rocky|oracle)$"; then
        DISTRO_FAMILY="rhel_family"
        LOCAL_SYSLOG_FILE_FOR_TESTS="/var/log/messages"
    else
        log "WARNING: Desteklenmeyen dağıtım ailesi. ID: $ID, ID_LIKE: $ID_LIKE"
        LOCAL_SYSLOG_FILE_FOR_TESTS="/var/log/syslog"  # Varsayılan fallback
    fi
else
    DISTRO="$(uname -s | tr '[:upper:]' '[:lower:]')"
    VERSION_ID_NUM="$(uname -r)"
    log "WARNING: /etc/os-release bulunamadı. Dağıtım tespiti sınırlı."
    LOCAL_SYSLOG_FILE_FOR_TESTS="/var/log/messages"
fi

log "Dağıtım Tespit Edildi: $DISTRO, Sürüm: $VERSION_ID_NUM, Aile: ${DISTRO_FAMILY:-unknown}"
log "Yerel sistem log testi dosyası: $LOCAL_SYSLOG_FILE_FOR_TESTS"

# --- Paket Kurulumu ---
install_packages() {
    log "Gerekli paketler kuruluyor..."
    if [[ "$DISTRO_FAMILY" == "debian_family" ]]; then
        log "APT tabanlı paket kurulumu: auditd, audispd-plugins, rsyslog, python3"
        apt-get update -y >> "$LOG_FILE" 2>&1 || error_exit "apt-get update başarısız."
        apt-get install -y auditd audispd-plugins rsyslog python3 >> "$LOG_FILE" 2>&1 \
            || error_exit "Paket kurulumu (apt-get) başarısız. Bağımlılıkları kontrol edin."
    elif [[ "$DISTRO_FAMILY" == "rhel_family" ]]; then
        log "YUM/DNF tabanlı paket kurulumu: audit, rsyslog, python3, rsyslog-omprog (gerekirse)"
        local rhel_extra_pkgs=""
        # RHEL 7/CentOS 7 için EPEL kontrolü
        if [[ "$VERSION_ID_NUM" == 7* ]]; then
            if ! yum list installed epel-release &>/dev/null; then
                log "EPEL yüklü değil. Kuruluyor..."
                yum install -y epel-release >> "$LOG_FILE" 2>&1 \
                    || log "WARNING: EPEL kurulamadı; python3 veya rsyslog-omprog bulunamayabilir."
                yum makecache fast >> "$LOG_FILE" 2>&1
            fi
            rhel_extra_pkgs="rsyslog-omprog"
        fi
        if command -v dnf &>/dev/null; then
            dnf install -y audit rsyslog python3 $rhel_extra_pkgs >> "$LOG_FILE" 2>&1 \
                || error_exit "Paket kurulumu (dnf) başarısız."
        else
            yum install -y audit rsyslog python3 $rhel_extra_pkgs >> "$LOG_FILE" 2>&1 \
                || error_exit "Paket kurulumu (yum) başarısız."
        fi
        # Python3 yoksa uyarı
        if ! command -v python3 &>/dev/null; then
            log "WARNING: python3 komutu sistemde bulunamadı. Python3 özellikleri kısıtlı olabilir."
        fi
    else
        error_exit "Desteklenmeyen dağıtım ailesi: '$DISTRO_FAMILY'."
    fi
    log "Gerekli paketler başarıyla kuruldu."
}

# --- Python Script Dağıtımı ---
deploy_python_script() {
    log "Python script ($PYTHON_SCRIPT_PATH) oluşturuluyor: EXECVE argüman birleştirmesi için..."
    cat > "$PYTHON_SCRIPT_PATH" << 'EOF'
#!/usr/bin/env python3
import sys
import re

def process_line(line):
    if "type=EXECVE" not in line:
        return line
    args = re.findall(r'a\d+="([^"]*)"', line)
    if args:
        combined_command = " ".join(args)
        escaped_combined = combined_command.replace('"', '\\"')
        new_line = re.sub(r'a\d+="(?:[^"\\]|\\.)*"\s*', '', line).strip()
        if new_line and not new_line.endswith(" "):
            new_line += " "
        new_line += 'a0="' + escaped_combined + '"'
        return new_line
    return line

def main():
    try:
        for line_in in sys.stdin:
            processed = process_line(line_in.strip())
            print(processed)
            sys.stdout.flush()
    except Exception as e:
        print(f"concat_execve_args.py ERROR: {e}", file=sys.stderr)

if __name__ == '__main__':
    main()
EOF

    chmod 755 "$PYTHON_SCRIPT_PATH" \
        || error_exit "Python script $PYTHON_SCRIPT_PATH çalıştırılabilir yapılamadı."
    chown root:root "$PYTHON_SCRIPT_PATH"
    log "Python script $PYTHON_SCRIPT_PATH oluşturuldu ve çalıştırılabilir yapıldı."
}

# --- Auditd Yapılandırması ---
configure_auditd() {
    log "auditd yapılandırması başlıyor..."

    # audisp-syslog binary konumunu tespit etmek için önce PATH içini kontrol et
    local audisp_syslog_binary=""
    if command -v audisp-syslog &>/dev/null; then
        audisp_syslog_binary="$(command -v audisp-syslog)"
    elif [ -x "/sbin/audisp-syslog" ]; then
        audisp_syslog_binary="/sbin/audisp-syslog"
    elif [ -x "/usr/sbin/audisp-syslog" ]; then
        audisp_syslog_binary="/usr/sbin/audisp-syslog"
    elif [ -x "/usr/libexec/audit/audisp-syslog" ]; then
        audisp_syslog_binary="/usr/libexec/audit/audisp-syslog"
    elif [ -x "/usr/lib/audit/audisp-syslog" ]; then
        audisp_syslog_binary="/usr/lib/audit/audisp-syslog"
    fi

    if [ -z "$audisp_syslog_binary" ]; then
        log "WARNING: audisp-syslog binary bulunamadı. audisp-plugin yapılandırması atlanacak."
    else
        log "audisp-syslog binary: $audisp_syslog_binary"
        # Audisp plugin yapılandırması
        mkdir -p "$(dirname "$AUDISP_PLUGIN_CONF_FILE")"
        UPPER_FACILITY="$(echo "$AUDIT_FACILITY" | tr '[:lower:]' '[:upper:]')"  # local3 -> LOCAL3
        cat > "$AUDISP_PLUGIN_CONF_FILE" << EOF
active = yes
direction = out
path = $audisp_syslog_binary
type = always
args = LOG_${UPPER_FACILITY}
format = string
EOF
        chmod 640 "$AUDISP_PLUGIN_CONF_FILE"
        log "Audisp plugin yapılandırıldı: $AUDISP_PLUGIN_CONF_FILE (facility: $AUDIT_FACILITY)"
    fi

    # Audit kuralları dizini ve dosyası
    mkdir -p "$AUDIT_RULES_D_DIR"
    cat > "$AUDIT_RULES_FILE" << 'EOF'
# ----- Birleşik Audit Kuralları -----
-D
-b 8192
-f 1

# Audit konfigürasyon değişiklikleri
-w /etc/audit/ -p wa -k audit_config_changes
-w /etc/libaudit.conf -p wa -k audit_config_changes
-w /etc/audisp/ -p wa -k audit_config_changes
-w /sbin/auditctl -p x -k audit_tool_usage
-w /sbin/auditd -p x -k audit_tool_usage
-w /var/log/audit/ -p rwa -k audit_log_access

# Kimlik ve erişim yönetimi
-w /etc/passwd -p wa -k iam_passwd_changes
-w /etc/shadow -p wa -k iam_shadow_changes
-w /etc/group -p wa -k iam_group_changes
-w /etc/gshadow -p wa -k iam_gshadow_changes
-w /etc/sudoers -p wa -k iam_sudoers_changes
-w /etc/sudoers.d/ -p wa -k iam_sudoers_d_changes
-w /etc/login.defs -p wa -k iam_login_defs_changes
-w /etc/security/opasswd -p wa -k iam_opasswd_changes
-w /var/log/faillog -p wa -k iam_faillog_access
-w /var/log/lastlog -p wa -k iam_lastlog_access
-w /etc/pam.d/ -p wa -k iam_pam_changes

# Sistem ve ağ yapılandırması
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k sys_net_config
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k sys_net_config
-w /etc/hosts -p wa -k sys_hosts_file

# Sistem durumu değişiklikleri
-w /sbin/shutdown -p x -k sys_state_change
-w /sbin/poweroff -p x -k sys_state_change
-w /sbin/reboot -p x -k sys_state_change
-w /sbin/halt -p x -k sys_state_change

# Kernel modülü değişiklikleri
-a always,exit -F path=/sbin/insmod -F perm=x -F auid>=1000 -F auid!=-1 -k kernel_module_change
-a always,exit -F path=/sbin/rmmod -F perm=x -F auid>=1000 -F auid!=-1 -k kernel_module_change
-a always,exit -F path=/sbin/modprobe -F perm=x -F auid>=1000 -F auid!=-1 -k kernel_module_change
-w /etc/modprobe.conf -p wa -k kernel_module_config
-w /etc/modprobe.d/ -p wa -k kernel_module_config

# Komut çalıştırma (Audit EXECVE kayıtları - saldırı tespiti için kritik)
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_execve
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_execve
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k user_execve
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k user_execve

# Yetki yükseltme ve değişiklikler
-w /bin/su -p x -k privilege_escalation_su
-w /usr/bin/sudo -p x -k privilege_escalation_sudo
-a always,exit -F arch=b64 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k privilege_syscalls
-a always,exit -F arch=b32 -S setuid -S setgid -S seteuid -S setegid -S setreuid -S setregid -S setresuid -S setresgid -k privilege_syscalls
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F a1&0111 -F auid>=1000 -F auid!=-1 -k privilege_perm_change
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F a1&0111 -F auid>=1000 -F auid!=-1 -k privilege_perm_change

# Şüpheli araç kullanımı
-w /usr/bin/wget -p x -k suspicious_utility_wget
-w /usr/bin/curl -p x -k suspicious_utility_curl
-w /bin/nc -p x -k suspicious_utility_netcat
-w /usr/bin/ncat -p x -k suspicious_utility_ncat

# Son: Kurallar korunur (immutable) - dikkatli kullanın
# -e 2
EOF

    # Dağıtıma özel ilave izlemeler
    if [[ "$DISTRO_FAMILY" == "rhel_family" ]]; then
        [ -d "/etc/sysconfig/network-scripts/" ] && {
            log "RHEL-specific izleme ekleniyor: /etc/sysconfig/network-scripts/"
            echo "-w /etc/sysconfig/network-scripts/ -p wa -k sys_rhel_netscripts" >> "$AUDIT_RULES_FILE"
        }
    elif [[ "$DISTRO_FAMILY" == "debian_family" ]]; then
        [ -f "/etc/network/interfaces" ] && {
            log "Debian-family izleme ekleniyor: /etc/network/interfaces"
            echo "-w /etc/network/interfaces -p wa -k sys_debian_interfaces" >> "$AUDIT_RULES_FILE"
        }
        [ -d "/etc/netplan" ] && {
            log "Ubuntu Netplan izleme ekleniyor: /etc/netplan/"
            echo "-w /etc/netplan/ -p wa -k sys_ubuntu_netplan" >> "$AUDIT_RULES_FILE"
        }
    fi

    chmod 640 "$AUDIT_RULES_FILE"
    log "Audit kuralları oluşturuldu: $AUDIT_RULES_FILE"

    # Audit kurallarını yükle
    log "Audit kuralları yükleniyor..."
    systemctl enable auditd >> "$LOG_FILE" 2>&1
    systemctl is-active --quiet auditd || systemctl restart auditd >> "$LOG_FILE" 2>&1

    if command -v augenrules &>/dev/null; then
        local AUGEN_STDERR="${LOG_FILE}.augenrules_stderr"
        if augenrules --load 2> "$AUGEN_STDERR"; then
            log "augenrules --load başarılı."
            sleep 1
            if ! auditctl -l | grep -q user_execve; then
                log "WARNING: Temel 'user_execve' kuralı auditctl -l çıktısında bulunamadı."
                [ -s "$AUGEN_STDERR" ] && log "augenrules stderr: $(cat "$AUGEN_STDERR")"
            else
                log "Audit kuralları yüklendi (user_execve tespit edildi)."
            fi
        else
            log "ERROR: augenrules --load başarısız. stderr:"
            cat "$AUGEN_STDERR" >> "$LOG_FILE"
            log "Kuralları gözden geçirin: $AUDIT_RULES_FILE"
            error_exit "augenrules --load başarısız."
        fi
        rm -f "$AUGEN_STDERR"
    else
        log "augenrules komutu yok. 'auditctl -R' ile kurallar yüklenecek (kalıcı değil)."
        auditctl -R "$AUDIT_RULES_FILE" >> "$LOG_FILE" 2>&1 \
            || error_exit "'auditctl -R' başarısız."
    fi

    systemctl restart auditd >> "$LOG_FILE" 2>&1 \
        || error_exit "auditd yeniden başlatılamadı."

    log "auditd servisi etkinleştirildi ve yeniden başlatıldı."
}

# --- Rsyslog Yapılandırması ---
configure_rsyslog() {
    log "rsyslog yapılandırması: Saldırı tespiti amaçlı audit kayıtları QRadar’a gönderilecek..."

    # Var olan konfigürasyonu yedekle
    if [ -f "$RSYSLOG_SIEM_CONF" ]; then
        cp -p "$RSYSLOG_SIEM_CONF" "${RSYSLOG_SIEM_CONF}.bak.$(date +%F_%T)" 2>/dev/null \
            || log "WARNING: $RSYSLOG_SIEM_CONF yedeklenemedi."
    fi

    cat > "$RSYSLOG_SIEM_CONF" << EOF
# ----- Birleşik SIEM Forwarding Konfigürasyonu -----

# omprog modülü komut tabanlı eylem için
module(load="omprog")

# Kernel mesajlarını işleme zincirinden çıkar
if \$syslogfacility-text == "kern" then {
    stop
}

# Yalnızca local3 facility (audit) kayıtlarını işlemek – yalnızca saldırı tespiti ile ilgili anahtarlar:
if \$syslogfacility-text == "$AUDIT_FACILITY" and (
       \$msg contains "type=EXECVE" 
    or \$msg contains "key=\"root_execve\"" 
    or \$msg contains "key=\"user_execve\"" 
    or \$msg contains "key=\"privilege_" 
    or \$msg contains "key=\"suspicious_utility_"
) then {
    # EXECVE içeren kayıtları öncelikle Python script ile dönüştür
    if \$msg contains "type=EXECVE" then {
        action(
            type="omprog"
            binary="$PYTHON_SCRIPT_PATH"
            name="TransformExecveForSIEM"
        )
    }

    # Tüm filtrelenen saldırı tespiti kayıtlarını QRadar’a TCP üzerinden gönder
    action(
        type="omfwd"
        target="$SIEM_IP"
        port="$SIEM_PORT"
        protocol="tcp"
        name="ForwardAuditToSIEM"
    )
    stop    # İlgili kayıt işlendi, başka zincirlere gitmesin
}
EOF

    log "Rsyslog SIEM yapılandırması yazıldı: $RSYSLOG_SIEM_CONF"

    log "Rsyslog konfig doğrulama yapılıyor..."
    RSYSLOG_VALID_LOG="${LOG_FILE}.rsyslog_validation"
    if rsyslogd -N1 > "$RSYSLOG_VALID_LOG" 2>&1; then
        log "Rsyslog ana konfigürasyonu başarılı şekilde doğrulandı."
        cat "$RSYSLOG_VALID_LOG" >> "$LOG_FILE"
    else
        log "WARNING: Rsyslog doğrulama satır hatası tespit etti. Detaylar log’da."
        cat "$RSYSLOG_VALID_LOG" >> "$LOG_FILE"
        # Yine de yeniden başlatmayı dene
    fi
    rm -f "$RSYSLOG_VALID_LOG"

    systemctl enable rsyslog >> "$LOG_FILE" 2>&1
    systemctl restart rsyslog >> "$LOG_FILE" 2>&1 \
        || error_exit "rsyslog yeniden başlatılamadı."

    log "Rsyslog servisi etkinleştirildi ve yeniden başlatıldı."
}

# --- OS’ye Özgü Ayarlar (RHEL Ailesi için SELinux/Firewall) ---
configure_os_specifics() {
    if [[ "$DISTRO_FAMILY" == "rhel_family" ]]; then
        log "RHEL ailesi için ek yapılandırmalar (SELinux, Firewalld)..."

        # SELinux: rsyslog’un ağ bağlantısı yapmasına izin ver
        if command -v getsebool &>/dev/null && command -v setsebool &>/dev/null; then
            local selinux_bool="syslogd_can_network_connect"
            if getsebool "$selinux_bool" | grep -q "--> on$"; then
                log "SELinux: $selinux_bool zaten etkin."
            else
                log "SELinux: $selinux_bool etkinleştiriliyor (kalıcı)..."
                setsebool -P "$selinux_bool" on >> "$LOG_FILE" 2>&1 \
                    && log "SELinux: $selinux_bool başarıyla etkinleştirildi." \
                    || log "WARNING: SELinux: $selinux_bool ayarlanamadı."
            fi
            log "Eğer omprog reddedilirse, 'ausearch -m avc -ts recent' ve 'chcon -t syslogd_script_exec_t $PYTHON_SCRIPT_PATH' komutlarını gözden geçirin."
        else
            log "SELinux komutları bulunamadı. Otomatik SELinux ayarı atlandı."
        fi

        # Firewalld: SIEM portunu aç
        if command -v firewall-cmd &>/dev/null; then
            if systemctl is-active --quiet firewalld; then
                log "Firewalld aktif. TCP port $SIEM_PORT açılıyor..."
                if ! firewall-cmd --query-port="$SIEM_PORT/tcp" --permanent &>/dev/null; then
                    firewall-cmd --permanent --add-port="$SIEM_PORT/tcp" >> "$LOG_FILE" 2>&1 \
                        && log "Firewalld: Port $SIEM_PORT/tcp kalıcı olarak eklendi." \
                        || log "WARNING: firewall-cmd --permanent --add-port=$SIEM_PORT/tcp başarısız."
                else
                    log "Firewalld: Port $SIEM_PORT/tcp zaten kalıcı kurallarda var."
                fi
                firewall-cmd --reload >> "$LOG_FILE" 2>&1 \
                    && log "Firewalld: Kurallar yeniden yüklendi." \
                    || log "WARNING: firewall-cmd --reload başarısız."
                if firewall-cmd --query-port="$SIEM_PORT/tcp" &>/dev/null; then
                    log "Firewalld: Port $SIEM_PORT/tcp çalışır durumda."
                else
                    log "WARNING: Firewalld: Port $SIEM_PORT/tcp aktif olmayabilir."
                fi
            else
                log "Firewalld aktif değil. Port açma adımı atlandı."
            fi
        else
            log "Firewalld (firewall-cmd) yok. Otomatik firewall yapılandırması atlandı."
        fi
    else
        log "RHEL ailesine özgü ayarlar atlandı (DISTRO_FAMILY: '$DISTRO_FAMILY')."
    fi
}

# --- Ana Akış ---
install_packages
deploy_python_script
configure_auditd
configure_rsyslog
configure_os_specifics

# --- Son Tanı/Kontrol ---
log "--- Final Tanı/Kontroller ---"
log "Servis durumları kontrol ediliyor..."
systemctl is-active --quiet auditd && log "Auditd servisi aktif." || log "WARNING: Auditd servisi çalışmıyor."
systemctl is-active --quiet rsyslog && log "Rsyslog servisi aktif." || log "WARNING: Rsyslog servisi çalışmıyor."

# Test amaçlı audit tetikleme
AUDIT_TEST_KEY="iam_passwd_changes"
log "Test audit olayı tetikleniyor: /etc/passwd dosyasına dokunma (key: $AUDIT_TEST_KEY)..."
touch /etc/passwd 2>/dev/null || log "WARNING: /etc/passwd dokunulamadı."
sleep 3

log "ausearch ile audit etkinliği aranıyor..."
if ausearch -k "$AUDIT_TEST_KEY" --raw --start today | grep -q "$AUDIT_TEST_KEY"; then
    log "SUCCESS: Test audit olayı ($AUDIT_TEST_KEY) bulundu."
else
    log "WARNING: Test audit olayı ($AUDIT_TEST_KEY) bulunamadı. Audit kurallarını kontrol edin."
fi

# Test amaçlı syslog gönderme
TEST_MSG="Unified script test log: facility=$AUDIT_FACILITY $(date)"
log "logger ile test mesajı gönderiliyor ($AUDIT_FACILITY): '$TEST_MSG'"
logger -p "$AUDIT_FACILITY.info" "$TEST_MSG"

log "Test mesajı ve audit olaylarının QRadar’da görünüp görünmediğini kontrol edin."
log "Sorun devam ederse, 'sudo tcpdump -i any host $SIEM_IP and port $SIEM_PORT -A -n' komutuyla ağ trafiğini inceleyin."
log "Ayrıca /var/log/audit/audit.log ve rsyslog günlüklerini gözden geçirin."

log "=== Unified Log Forwarding Kurulum Betiği Tamamlandı ==="
exit 0
