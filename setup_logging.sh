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

## Hataları yoksayma
-i

##########################################
# [Kendi Kendini Denetleme]
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
# İşlem Yürütme İzleme
##########################################
-a always,exit -F arch=b64 -F euid=0 -S execve -k root_command
-a always,exit -F arch=b32 -F euid=0 -S execve -k root_command
-a always,exit -F arch=b64 -F euid>=1000 -S execve -k user_command
-a always,exit -F arch=b32 -F euid>=1000 -S execve -k user_command

##########################################
# Ağ Konfigürasyon Değişiklikleri
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
# Çekirdek Modül Yükleme
##########################################
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k kernel_modules
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k kernel_modules
-w /etc/modprobe.conf -p wa -k kernel_modules

##########################################
# Kimlik Doğrulama Olayları (PAM vb.)
##########################################
-w /etc/pam.d/ -p wa -k pam_modifications
-w /var/log/faillog -p wa -k login_modifications
-w /var/log/lastlog -p wa -k login_modifications

##########################################
# Yetki Yükseltme
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
# Tüm Kullanıcı Komutlarını İzleme
##########################################
# Tüm kullanıcıların çalıştırdığı komutları loglamak için execve izleme
-a always,exit -F arch=b64 -S execve -k user_commands
-a always,exit -F arch=b32 -S execve -k user_commands
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

    # Rsyslog servis durumu
    systemctl is-active rsyslog &>/dev/null
    if [ $? -ne 0 ]; then
        log "Rsyslog servisi aktif değil. Başlatılıyor."
        systemctl start rsyslog &>> "$LOG_FILE" || {
            log "HATA: Rsyslog servisi başlatılamadı."
            return
        }
        log "Rsyslog servisi başarıyla başlatıldı."
    else
        log "Rsyslog servisi aktif."
    fi

    # Rsyslog konfigürasyonunu kontrol et
    rsyslogd -N1 &>> "$LOG_FILE"
    if [ $? -eq 0 ]; then
        log "Rsyslog konfigürasyon doğrulandı. Herhangi bir hata bulunmadı."
    else
        log "HATA: Rsyslog konfigürasyonunda hata var. Hataları düzeltmek için script yeniden yapılandırmayı deniyor."
        fix_rsyslog_config
    fi

    # Rsyslog loglarını kontrol et
    if [ -f "$SYSLOG_FILE" ]; then
        log "$SYSLOG_FILE dosyası mevcut."
    else
        log "HATA: $SYSLOG_FILE dosyası bulunamadı."
    fi

    # Rsyslog yapılandırma dosyasının doğru olup olmadığını kontrol et
    if grep -Fxq "local1.* @@${SIEM_IP}:${SIEM_PORT}" /etc/rsyslog.d/60-siem.conf; then
        log "Rsyslog SIEM konfigürasyonu doğru."
    else
        log "HATA: /etc/rsyslog.d/60-siem.conf dosyasında SIEM konfigürasyonu bulunamadı veya hatalı."
        fix_rsyslog_config
    fi

    log "----- RSYSLOG Diagnostic Bitti -----"
}

diagnose_auditd() {
    log "----- AUDITD Diagnostic -----"

    # Auditd servis durumu
    systemctl is-active auditd &>/dev/null
    if [ $? -ne 0 ]; then
        log "Auditd servisi aktif değil. Başlatılıyor."
        systemctl start auditd &>> "$LOG_FILE" || {
            log "HATA: Auditd servisi başlatılamadı."
            return
        }
        log "Auditd servisi başarıyla başlatıldı."
    else
        log "Auditd servisi aktif."
    fi

    # Auditd loglarını kontrol et
    if grep -iq "error" "$AUDITD_LOG_FILE"; then
        log "HATA: Auditd loglarında hata bulundu."
    else
        log "Auditd loglarında herhangi bir hata bulunamadı."
    fi

    # Audit kurallarını doğrulama
    if auditctl -l | grep -q "user_commands"; then
        log "Audit kuralları doğru şekilde yüklendi."
    else
        log "HATA: Audit kuralları doğru şekilde yüklenmedi."
        fix_audisp_syslog_config
    fi

    log "----- AUDITD Diagnostic Bitti -----"
}

diagnose_permissions() {
    log "----- Permissions Diagnostic -----"

    # SYSLOG_FILE izinlerini kontrol et
    if [ -f "$SYSLOG_FILE" ]; then
        ls -l "$SYSLOG_FILE" &>> "$LOG_FILE"
        if [ $? -ne 0 ]; then
            log "HATA: $SYSLOG_FILE dosyası bulunamadı."
        else
            log "$SYSLOG_FILE dosyası mevcut."
            # İzinlerin doğru olup olmadığını kontrol et (örneğin, rsyslog tarafından yazılabilir olması)
            if [ ! -w "$SYSLOG_FILE" ]; then
                log "HATA: $SYSLOG_FILE dosyasının yazma izinleri yok."
                chmod 644 "$SYSLOG_FILE" &>> "$LOG_FILE" || {
                    log "HATA: $SYSLOG_FILE dosyasının izinleri düzeltilemedi."
                }
                log "$SYSLOG_FILE dosyasının izinleri düzeltildi."
            else
                log "$SYSLOG_FILE dosyasının yazma izinleri mevcut."
            fi
        fi
    else
        log "HATA: $SYSLOG_FILE dosyası bulunamadı."
    fi

    log "----- Permissions Diagnostic Bitti -----"
}

diagnose_selinux_apparmor() {
    log "----- SELinux/AppArmor Diagnostic -----"

    # SELinux durumu
    if command -v getenforce &>/dev/null; then
        SELINUX_STATUS=$(getenforce)
        log "SELinux durumu: $SELINUX_STATUS"
        if [ "$SELINUX_STATUS" != "Disabled" ]; then
            log "SELinux etkin. Rsyslog ve Auditd için gerekli izinlerin olduğundan emin olun."
        else
            log "SELinux devre dışı."
        fi
    else
        log "SELinux kontrol edilemiyor."
    fi

    # AppArmor durumu
    if command -v aa-status &>/dev/null; then
        APPARMOR_STATUS=$(aa-status | grep "profiles are in enforce mode")
        if [ -n "$APPARMOR_STATUS" ]; then
            log "AppArmor etkin. Rsyslog ve Auditd için gerekli izinlerin olduğundan emin olun."
        else
            log "AppArmor devre dışı."
        fi
    else
        log "AppArmor kontrol edilemiyor."
    fi

    log "----- SELinux/AppArmor Diagnostic Bitti -----"
}

# Otomatik düzeltme fonksiyonları
fix_rsyslog_config() {
    log "Rsyslog konfigürasyonunu düzeltmeye çalışıyor."

    # 60-siem.conf dosyasını yeniden oluştur
    cat <<EOF > /etc/rsyslog.d/60-siem.conf
# Forward local1.* to SIEM
local1.* @@${SIEM_IP}:${SIEM_PORT}
EOF

    # Rsyslog'u yeniden başlat
    systemctl restart rsyslog &>> "$LOG_FILE" || {
        log "HATA: Rsyslog servisi yeniden başlatılamadı."
        return
    }

    log "Rsyslog servisi başarıyla yeniden başlatıldı."

    # Rsyslog konfigürasyonunu doğrulama
    rsyslogd -N1 &>> "$LOG_FILE"
    if [ $? -eq 0 ]; then
        log "Rsyslog konfigürasyon doğrulandı. Herhangi bir hata bulunmadı."
    else
        log "HATA: Rsyslog konfigürasyonunda hata var. Lütfen /etc/rsyslog.d/60-siem.conf dosyasını manuel olarak kontrol edin."
    fi
}

fix_audisp_syslog_config() {
    log "Audisp-syslog plugin konfigürasyonunu düzeltmeye çalışıyor."

    # syslog.conf dosyasını yeniden oluştur
    cat <<EOF > /etc/audit/plugins.d/syslog.conf
active = yes
direction = out
path = /usr/sbin/audisp-syslog
type = always
args = LOG_LOCAL1
format = string
EOF

    chmod 640 /etc/audit/plugins.d/syslog.conf &>> "$LOG_FILE" || {
        log "HATA: Syslog plugin dosya izinleri düzeltilemedi."
        return
    }

    log "Syslog plugin dosya izinleri düzeltildi."

    # Auditd'yi yeniden başlat
    systemctl restart auditd &>> "$LOG_FILE" || {
        log "HATA: Auditd servisi yeniden başlatılamadı."
        return
    }

    log "Auditd servisi başarıyla yeniden başlatıldı."

    # Audit kurallarını tekrar yükle
    if command -v augenrules &>/dev/null; then
        augenrules --load &>> "$LOG_FILE" || {
            log "HATA: Audit kuralları yüklenemedi. Lütfen /etc/audit/rules.d/audit.rules dosyasını manuel olarak kontrol edin."
            return
        }
        log "Audit kuralları başarıyla yüklendi."
    else
        log "augenrules komutu bulunamadı. Audit kurallarını elle kontrol edin."
    fi
}

# Root yetkisi kontrolü
if [ "$EUID" -ne 0 ]; then
    echo "Lütfen script'i root yetkisiyle çalıştırın."
    exit 1
fi

# Argüman kontrolü
if [ -z "$SIEM_IP" ] || [ -z "$SIEM_PORT" ]; then
    echo "Kullanım: $0 <SIEM_IP> <SIEM_PORT>"
    exit 1
fi

# Log dosyasını oluştur ve izinlerini ayarla
touch "$LOG_FILE" &>/dev/null || {
    echo "Log dosyası oluşturulamıyor."
    exit 1
}

chmod 600 "$LOG_FILE" &>/dev/null || {
    echo "Log dosyası izinleri ayarlanamadı."
    exit 1
}

log "=== Loglama yapılandırma scripti başlıyor ==="
log "SIEM IP: $SIEM_IP, Port: $SIEM_PORT"

# Dağıtım tespiti
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    VERSION_ID=$VERSION_ID
else
    DISTRO=$(uname -s)
    VERSION_ID=$(uname -r)
fi

log "Dağıtım: $DISTRO, Versiyon: $VERSION_ID"

# Syslog dosyasını belirleme
case "$DISTRO" in
    ubuntu|debian|kali)
        SYSLOG_FILE="/var/log/syslog"
        ;;
    rhel|centos|oracle)
        SYSLOG_FILE="/var/log/messages"
        ;;
    *)
        error_exit "Bu script şu an sadece Debian/Ubuntu/Kali, Red Hat/CentOS, ve Oracle Linux için desteklenmektedir."
        ;;
esac

log "Kullanılan Syslog dosyası: $SYSLOG_FILE"

# Paket kurulum fonksiyonu
install_packages() {
    case "$DISTRO" in
        ubuntu|debian|kali)
            log "Debian/Ubuntu/Kali tabanlı sistemler için paket kurulumu başlatılıyor."
            apt-get update &>> "$LOG_FILE" || {
                log "HATA: apt-get update başarısız."
                error_exit "apt-get update başarısız."
            }
            apt-get install -y auditd audispd-plugins rsyslog &>> "$LOG_FILE" || {
                log "HATA: Gerekli paketler kurulamadı."
                error_exit "Gerekli paketler kurulamadı."
            }
            ;;
        rhel|centos|oracle)
            log "Red Hat/CentOS/Oracle Linux tabanlı sistemler için paket kurulumu başlatılıyor."
            if command -v dnf &> /dev/null; then
                dnf install -y audit rsyslog &>> "$LOG_FILE" || {
                    log "HATA: Gerekli paketler dnf ile kurulamadı."
                    error_exit "Gerekli paketler dnf ile kurulamadı."
                }
            else
                yum install -y audit rsyslog &>> "$LOG_FILE" || {
                    log "HATA: Gerekli paketler yum ile kurulamadı."
                    error_exit "Gerekli paketler yum ile kurulamadı."
                }
            fi
            ;;
        *)
            error_exit "Bu script şu an sadece Debian/Ubuntu/Kali, Red Hat/CentOS, ve Oracle Linux için desteklenmektedir."
            ;;
    esac
}

install_packages
log "Paketler başarıyla kuruldu."

# Auditd servisini başlat ve etkinleştir
log "Auditd servisini başlatılıyor ve etkinleştiriliyor."
systemctl enable auditd &>> "$LOG_FILE" || {
    log "HATA: auditd servisi etkinleştirilemedi."
    error_exit "auditd servisi etkinleştirilemedi."
}

systemctl start auditd &>> "$LOG_FILE" || {
    log "HATA: auditd servisi başlatılamadı."
    error_exit "auditd servisi başlatılamadı."
}
log "auditd servisi başarıyla başlatıldı."

# Audisp-syslog plugin yapılandırması
SYSLOG_CONF="/etc/audit/plugins.d/syslog.conf"

# audisp-syslog binary yolu kontrolü
if [ -f "/usr/sbin/audisp-syslog" ]; then
    AUDISP_SYSLOG_PATH="/usr/sbin/audisp-syslog"
elif [ -f "/usr/lib/audisp/audisp-syslog" ]; then
    AUDISP_SYSLOG_PATH="/usr/lib/audisp/audisp-syslog"
else
    log "HATA: audisp-syslog binary'si bulunamadı."
    error_exit "audisp-syslog binary'si bulunamadı."
fi

log "Audisp-syslog binary yolu: $AUDISP_SYSLOG_PATH"

# syslog.conf dosyasını yapılandırma
cat <<EOF > "$SYSLOG_CONF"
active = yes
direction = out
path = $AUDISP_SYSLOG_PATH
type = always
args = LOG_LOCAL1
format = string
EOF

chmod 640 "$SYSLOG_CONF" &>> "$LOG_FILE" || {
    log "HATA: Syslog plugin dosya izinleri ayarlanamadı."
    error_exit "Syslog plugin dosya izinleri ayarlanamadı."
}

log "audisp syslog plugin ayarları yapıldı: $SYSLOG_CONF"

# Auditd'yi yeniden başlat
systemctl restart auditd &>> "$LOG_FILE" || {
    log "HATA: auditd servisi yeniden başlatılamadı."
    error_exit "auditd servisi yeniden başlatılamadı."
}
log "auditd servisi yeniden başlatıldı."

# Rsyslog konfigürasyonu - SIEM'e log iletimi
RSYSLOG_SIEM_CONF="/etc/rsyslog.d/60-siem.conf"

cat <<EOF > "$RSYSLOG_SIEM_CONF"
# Forward local1.* to SIEM
local1.* @@${SIEM_IP}:${SIEM_PORT}
EOF

log "Rsyslog konfigürasyonu oluşturuldu: $RSYSLOG_SIEM_CONF"

# Rsyslog'u yeniden başlat
systemctl restart rsyslog &>> "$LOG_FILE" || {
    log "HATA: rsyslog servisi yeniden başlatılamadı."
    error_exit "rsyslog servisi yeniden başlatılamadı."
}
log "rsyslog servisi yeniden başlatıldı."

# Audit kurallarını ekleme
AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"

log "Audit kuralları dosyası oluşturuluyor: $AUDIT_RULES_FILE"

echo "$AUDIT_RULES_CONTENT" > "$AUDIT_RULES_FILE" || {
    log "HATA: Audit kuralları dosyası oluşturulamadı."
    error_exit "Audit kuralları dosyası oluşturulamadı."
}

chmod 640 "$AUDIT_RULES_FILE" || {
    log "HATA: Audit kuralları dosya izinleri ayarlanamadı."
    error_exit "Audit kuralları dosya izinleri ayarlanamadı."
}
log "Audit kuralları dosyası oluşturuldu: $AUDIT_RULES_FILE"

# Audit kurallarını yükle
if command -v augenrules &>/dev/null; then
    augenrules --load &>> "$LOG_FILE" || {
        log "HATA: Audit kuralları yüklenemedi."
        error_exit "Audit kuralları yüklenemedi."
    }
    log "Audit kuralları başarıyla yüklendi."
else
    log "augenrules komutu bulunamadı. Audit kurallarını elle kontrol edin."
    # Alternatif olarak, auditctl ile kuralları yükleyebilirsiniz
    auditctl -R "$AUDIT_RULES_FILE" &>> "$LOG_FILE" || {
        log "HATA: Audit kuralları auditctl ile yüklenemedi."
        error_exit "Audit kuralları auditctl ile yüklenemedi."
    }
    log "Audit kuralları auditctl ile başarıyla yüklendi."
fi

log "Audit kuralları başarıyla yüklendi."

# Auditd'yi yeniden başlat
systemctl restart auditd &>> "$LOG_FILE" || {
    log "HATA: auditd servisi yeniden başlatılamadı."
    error_exit "auditd servisi yeniden başlatılamadı."
}
log "auditd servisi yeniden başlatıldı."

# Test 1: Local syslog test
log "Test mesajı yerel syslog'a gönderiliyor."
logger "Test message from setup_logging.sh script."
sleep 2

if grep -q "Test message from setup_logging.sh script." "$SYSLOG_FILE"; then
    log "Test mesajı yerel syslog'da bulundu."
else
    log "Uyarı: Test mesajı yerel syslog'da bulunamadı."
    log "Rsyslog konfigürasyonunu kontrol ediyor ve düzeltmeye çalışıyor."
    diagnose_rsyslog
    log "Test mesajını yeniden gönderiyor."
    logger "Test message from setup_logging.sh script."
    sleep 2
    if grep -q "Test message from setup_logging.sh script." "$SYSLOG_FILE"; then
        log "Test mesajı yerel syslog'da bulundu."
    else
        log "HATA: Test mesajı yerel syslog'da bulunamadı."
        diagnose_rsyslog
    fi
fi

# Test 2: Audit log testi
log "/etc/passwd dosyasına dokunularak audit log testi yapılıyor."
touch /etc/passwd
sleep 2

if ausearch -k passwd_modifications | grep -q "name=\"/etc/passwd\""; then
    log "Audit log üretildi (passwd_modifications)."
else
    log "Uyarı: Audit log /etc/passwd değişikliği için üretilmedi!"
    log "Auditd ve Audisp-syslog konfigürasyonunu kontrol ediyor ve düzeltmeye çalışıyor."
    diagnose_auditd
    log "/etc/passwd dosyasına yeniden dokunarak audit log testi yapılıyor."
    touch /etc/passwd
    sleep 2
    if ausearch -k passwd_modifications | grep -q "name=\"/etc/passwd\""; then
        log "Audit log üretildi (passwd_modifications)."
    else
        log "HATA: Audit log /etc/passwd değişikliği için üretilmedi!"
        diagnose_auditd
    fi
fi

if grep -q "passwd_modifications" "$SYSLOG_FILE"; then
    log "Audit log syslog üzerinden tespit edildi."
else
    log "Uyarı: Audit log syslog'a düşmedi."
    log "Auditd ve Audisp-syslog konfigürasyonunu kontrol ediyor ve düzeltmeye çalışıyor."
    diagnose_auditd
    log "/etc/passwd dosyasına yeniden dokunarak audit log testi yapılıyor."
    touch /etc/passwd
    sleep 2
    if grep -q "passwd_modifications" "$SYSLOG_FILE"; then
        log "Audit log syslog üzerinden tespit edildi."
    else
        log "HATA: Audit log syslog'a düşmedi."
        diagnose_auditd
    fi
fi

# Permissions Diagnostic
diagnose_permissions

# SELinux/AppArmor Diagnostic
diagnose_selinux_apparmor

# Doğrulama: Audit loglarının SIEM'e iletilip iletilmediğini kontrol etmek için tcpdump önerisi
log "Audit loglarının SIEM'e iletilip iletilmediğini doğrulamak için SIEM sunucusunda tcpdump kullanabilirsiniz."
log "Örnek komut: sudo tcpdump -i eth0 host $SIEM_IP and port $SIEM_PORT -nn -vv"

log "=== Loglama yapılandırma scripti tamamlandı ==="
exit 0
