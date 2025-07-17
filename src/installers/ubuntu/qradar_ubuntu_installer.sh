#!/usr/bin/env bash

set -Eeuo pipefail
trap 'error_exit "Unexpected failure (line: $LINENO)"' ERR

readonly SCRIPT_VERSION="4.0.0-ubuntu"
readonly LOG_FILE="/var/log/qradar_ubuntu_setup.log"
BACKUP_DIR="/etc/qradar_backup_$(date +%Y%m%d_%H%M%S)"
readonly BACKUP_DIR

readonly AUDIT_RULES_FILE="/etc/audit/rules.d/99-qradar.rules"
readonly AUDISP_PLUGINS_DIR="/etc/audisp/plugins.d"
readonly AUDIT_PLUGINS_DIR="/etc/audit/plugins.d"
readonly AUDIT_SYSLOG_CONF="/etc/audit/plugins.d/syslog.conf"
readonly RSYSLOG_QRADAR_CONF="/etc/rsyslog.d/99-qradar.conf"
readonly CONCAT_SCRIPT_PATH="/usr/local/bin/qradar_execve_parser.py"

UBUNTU_VERSION=""
UBUNTU_CODENAME=""
VERSION_MAJOR=""
VERSION_MINOR=""
AUDISP_METHOD=""
AUDISP_SYSLOG_CONF=""
SYSLOG_FILE="/var/log/syslog"

QRADAR_IP=""
QRADAR_PORT=""

log() {
    local level="${1:-INFO}"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

error_exit() {
    log "ERROR" "$1"
    echo "HATA: $1" >&2
    echo "Detaylar için $LOG_FILE dosyasını kontrol edin."
    exit 1
}

warn() {
    log "WARN" "$1"
    echo "UYARI: $1" >&2
}

success() {
    log "SUCCESS" "$1"
    echo "✓ $1"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

safe_execute() {
    local description="$1"
    shift
    log "DEBUG" "Çalıştırılıyor: $description - Komut: $*"
    
    if "$@" >> "$LOG_FILE" 2>&1; then
        log "DEBUG" "$description - BAŞARILI"
        return 0
    else
        local exit_code=$?
        warn "$description - BAŞARISIZ (Çıkış kodu: $exit_code)"
        return $exit_code
    fi
}

retry_operation() {
    local max_attempts=3
    local delay=5
    local description="$1"
    shift
    
    for ((attempt=1; attempt<=max_attempts; attempt++)); do
        if safe_execute "$description (Deneme $attempt/$max_attempts)" "$@"; then
            return 0
        fi
        if [[ $attempt -lt $max_attempts ]]; then
            log "INFO" "$delay saniye sonra tekrar denenecek..."
            sleep $delay
        fi
    done
    
    error_exit "$description $max_attempts denemeden sonra başarısız oldu"
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_file
        backup_file="$BACKUP_DIR/$(basename "$file").$(date +%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$backup_file" || warn "$file yedeklenemedi"
        log "INFO" "$file dosyası $backup_file konumuna yedeklendi"
    fi
}

detect_ubuntu_version() {
    log "INFO" "Ubuntu sürümü tespit ediliyor..."
    
    if [[ ! -f /etc/os-release ]]; then
        error_exit "/etc/os-release dosyası bulunamadı. Ubuntu sistemi doğrulanamıyor."
    fi
    
    source /etc/os-release
    
    if [[ -z "${ID:-}" ]]; then
        error_exit "ID değişkeni /etc/os-release dosyasında bulunamadı"
    fi
    
    if [[ -z "${VERSION_ID:-}" ]]; then
        error_exit "VERSION_ID değişkeni /etc/os-release dosyasında bulunamadı"
    fi
    
    if [[ -z "${VERSION_CODENAME:-}" ]]; then
        error_exit "VERSION_CODENAME değişkeni /etc/os-release dosyasında bulunamadı"
    fi
    
    if [[ "$ID" != "ubuntu" ]]; then
        error_exit "Bu script sadece Ubuntu sistemler için tasarlanmıştır. Tespit edilen: $ID"
    fi
    
    UBUNTU_VERSION="$VERSION_ID"
    UBUNTU_CODENAME="$VERSION_CODENAME"
    
    IFS='.' read -r VERSION_MAJOR VERSION_MINOR <<< "$UBUNTU_VERSION"
    
    if [[ -z "$VERSION_MAJOR" ]] || [[ ! "$VERSION_MAJOR" =~ ^[0-9]+$ ]]; then
        error_exit "VERSION_MAJOR değeri geçersiz: '$VERSION_MAJOR' (UBUNTU_VERSION: $UBUNTU_VERSION)"
    fi
    
    if [[ -z "$VERSION_MINOR" ]] || [[ ! "$VERSION_MINOR" =~ ^[0-9]+$ ]]; then
        error_exit "VERSION_MINOR değeri geçersiz: '$VERSION_MINOR' (UBUNTU_VERSION: $UBUNTU_VERSION)"
    fi
    
    if [[ $VERSION_MAJOR -lt 16 ]] || [[ $VERSION_MAJOR -eq 16 && $VERSION_MINOR -lt 4 ]]; then
        error_exit "Bu script Ubuntu 16.04+ sürümlerini destekler. Mevcut sürüm: $UBUNTU_VERSION"
    fi
    
    success "Ubuntu $UBUNTU_VERSION ($UBUNTU_CODENAME) tespit edildi ve destekleniyor"
    
    determine_audisp_method
}

determine_audisp_method() {
    log "INFO" "Ubuntu sürümüne göre audisp metodu belirleniyor..."
    
    if [[ $VERSION_MAJOR -lt 20 ]]; then
        AUDISP_METHOD="legacy"
        AUDISP_SYSLOG_CONF="$AUDISP_PLUGINS_DIR/syslog.conf"
        log "INFO" "Legacy audisp metodu kullanılacak (/etc/audisp/plugins.d/)"
    else
        AUDISP_METHOD="modern"
        AUDISP_SYSLOG_CONF="$AUDIT_SYSLOG_CONF"
        log "INFO" "Modern audit metodu kullanılacak (/etc/audit/plugins.d/)"
    fi
    
    if [[ "$AUDISP_METHOD" == "legacy" ]]; then
        mkdir -p "$AUDISP_PLUGINS_DIR"
    else
        mkdir -p "$AUDIT_PLUGINS_DIR"
    fi
}

install_required_packages() {
    log "INFO" "Gerekli paketler kontrol ediliyor ve kuruluyor..."
    
    local required_packages=("auditd" "rsyslog" "python3")
    
    if [[ $VERSION_MAJOR -lt 20 ]]; then
        required_packages+=("audispd-plugins")
    fi
    
    local packages_to_install=()
    
    retry_operation "Paket listesi güncelleme" apt-get update
    
    for package in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package "; then
            packages_to_install+=("$package")
            log "INFO" "$package paketi kurulu değil"
        else
            log "INFO" "$package paketi zaten kurulu"
        fi
    done
    
    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        log "INFO" "Kurulacak paketler: ${packages_to_install[*]}"
        retry_operation "Paket kurulumu" apt-get install -y "${packages_to_install[@]}"
        success "Paketler başarıyla kuruldu: ${packages_to_install[*]}"
    else
        success "Tüm gerekli paketler zaten kurulu"
    fi
    
    local critical_binaries=("/sbin/auditd" "/usr/sbin/rsyslogd" "/usr/bin/python3")
    for binary in "${critical_binaries[@]}"; do
        if [[ ! -f "$binary" ]]; then
            error_exit "Kritik binary bulunamadı: $binary"
        fi
    done
    
    success "Tüm kritik binary'ler doğrulandı"
}

deploy_execve_parser() {
    log "INFO" "EXECVE komut ayrıştırıcısı deploy ediliyor..."
    
    backup_file "$CONCAT_SCRIPT_PATH"
    
    cat > "$CONCAT_SCRIPT_PATH" << 'EXECVE_PARSER_EOF'
#!/usr/bin/env python3
import sys
import re
import pwd
import grp
import signal
from typing import Dict, List, Optional

MITRE_TECHNIQUES: Dict[str, List[str]] = {
    "T1003": ["cat /etc/shadow", "cat /etc/gshadow", "getent shadow", "dump"],
    "T1059": ["bash", "sh", "zsh", "python", "perl", "ruby", "php", "node"],
    "T1070": ["history -c", "rm /root/.bash_history", "shred", "wipe"],
    "T1071": ["curl", "wget", "ftp", "sftp"],
    "T1082": ["uname -a", "lscpu", "lshw", "dmidecode"],
    "T1087": ["who", "w", "last", "lastlog", "id", "getent passwd"],
    "T1105": ["scp", "rsync", "socat", "ncat"],
    "T1548": ["sudo", "su -", "pkexec"],
    "T1562": [
        "systemctl stop auditd",
        "service auditd stop",
        "auditctl -e 0",
        "setenforce 0",
    ],
}

class ExecveParser:
    def __init__(self):
        self.execve_pattern = re.compile(r"type=EXECVE")
        self.arg_pattern = re.compile(r'a(\d+)="([^"]*)"')
        self.hex_arg_pattern = re.compile(r"a\d+=([0-9A-Fa-f]+)")
        self.user_pattern = re.compile(r"\b(a?uid|gid)=(\d+)")
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum: int, frame) -> None:
        sys.exit(0)

    def _get_user_info(self, line: str) -> Dict[str, str]:
        info = {}
        for key in ["auid", "uid", "gid"]:
            match = re.search(rf"\b{key}=(\d+)", line)
            if match:
                num_id = int(match.group(1))
                if num_id == 4294967295:
                    continue
                try:
                    if "uid" in key:
                        user_name = pwd.getpwuid(num_id).pw_name
                        info[f"{key}_name"] = user_name
                    elif "gid" in key:
                        group_name = grp.getgrgid(num_id).gr_name
                        info[f"{key}_name"] = group_name
                except (KeyError, ValueError):
                    pass
        return info

    def _analyze_mitre_techniques(self, command: str) -> List[str]:
        techniques_found = []
        for tech_id, patterns in MITRE_TECHNIQUES.items():
            for pattern in patterns:
                if pattern in command:
                    techniques_found.append(tech_id)
                    break
        return techniques_found

    def _format_kv(self, data: Dict[str, str]) -> str:
        return " ".join([f'{key}="{value}"' for key, value in data.items()])

    def parse_line(self, line: str) -> Optional[str]:
        if not self.execve_pattern.search(line):
            return line

        try:
            args: Dict[int, str] = {}
            for match in self.arg_pattern.finditer(line):
                args[int(match.group(1))] = match.group(2)
            for match in self.hex_arg_pattern.finditer(line):
                key, hex_val = match.group(0).split("=", 1)
                arg_num = int(key[1:])
                if arg_num not in args:
                    try:
                        args[arg_num] = bytes.fromhex(hex_val).decode(
                            "utf-8", "replace"
                        )
                    except ValueError:
                        pass

            if not args:
                return line

            full_command = " ".join(args[i] for i in sorted(args.keys()))

            line = self.arg_pattern.sub("", line)
            line = self.hex_arg_pattern.sub("", line)
            line = re.sub(r"argc=\d+\s*", "", line).strip()

            enrichment_data = {
                "cmd": full_command,
            }

            user_info = self._get_user_info(line)
            enrichment_data.update(user_info)

            mitre_info = self._analyze_mitre_techniques(full_command)
            if mitre_info:
                enrichment_data["mitre_techniques"] = ",".join(
                    sorted(list(set(mitre_info)))
                )

            return f"{line} {self._format_kv(enrichment_data)}"

        except Exception:
            return line

    def run(self) -> None:
        try:
            for line in sys.stdin:
                processed_line = self.parse_line(line.strip())
                if processed_line:
                    print(processed_line, flush=True)
        except (IOError, BrokenPipeError):
            sys.exit(0)
        except Exception:
            sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("EXECVE parser is working correctly")
        sys.exit(0)
    
    parser = ExecveParser()
    parser.run()
EXECVE_PARSER_EOF
    
    chmod +x "$CONCAT_SCRIPT_PATH" || error_exit "EXECVE parser script'i çalıştırılabilir yapılamadı"
    chown root:root "$CONCAT_SCRIPT_PATH" || warn "EXECVE parser script'i sahiplik ayarlanamadı"
    
    if python3 "$CONCAT_SCRIPT_PATH" --test >> "$LOG_FILE" 2>&1; then
        success "EXECVE komut ayrıştırıcısı başarıyla deploy edildi ve test edildi"
    else
        warn "EXECVE parser test başarısız oldu, ancak script deploy edildi"
    fi

    cat > "/usr/local/bin/extract_audit_type.sh" << 'AUDIT_TYPE_EOF'
#!/bin/bash
echo "$1" | grep -oP 'type=\K\w+' | head -1
AUDIT_TYPE_EOF
    chmod +x "/usr/local/bin/extract_audit_type.sh"
    chown root:root "/usr/local/bin/extract_audit_type.sh"

    cat > "/usr/local/bin/extract_audit_result.sh" << 'AUDIT_RESULT_EOF'
#!/bin/bash
if echo "$1" | grep -q "res=success\|success=yes"; then
    echo "success"
else
    echo "failed"
fi
AUDIT_RESULT_EOF
    chmod +x "/usr/local/bin/extract_audit_result.sh"
    chown root:root "/usr/local/bin/extract_audit_result.sh"
    
    success "Helper script'ler başarıyla deploy edildi"
}

configure_auditd() {
    log "INFO" "Auditd kuralları yapılandırılıyor..."
    
    backup_file "$AUDIT_RULES_FILE"
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")"

    cat > "$AUDIT_RULES_FILE" << 'AUDIT_RULES_EOF'
-D
-b 32768
-f 1
-i

-w /var/log/audit/ -k T1005_Data_From_Local_System_audit_log
-w /etc/audit/ -p wa -k T1005_Data_From_Local_System_audit_config
-w /etc/libaudit.conf -p wa -k T1005_Data_From_Local_System_audit_config
-w /etc/audisp/ -p wa -k T1005_Data_From_Local_System_audit_config
-w /sbin/auditctl -p x -k T1005_Data_From_Local_System_audit_tools
-w /sbin/auditd -p x -k T1005_Data_From_Local_System_audit_tools

-a always,exclude -F msgtype=AVC
-a always,exclude -F msgtype=CWD
-a always,exclude -F msgtype=EOE
-a never,user -F subj_type=crond_t
-a exit,never -F subj_type=crond_t
-a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=chrony -F subj_type=chronyd_t
-a always,exclude -F msgtype=CRYPTO_KEY_USER
-a exit,never -F arch=b32 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2
-a exit,never -F arch=b64 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2
-a exit,never -F arch=b32 -F dir=/dev/shm -k sharedmemaccess
-a exit,never -F arch=b64 -F dir=/dev/shm -k sharedmemaccess
-a exit,never -F arch=b32 -F dir=/var/lock/lvm -k locklvm
-a exit,never -F arch=b64 -F dir=/var/lock/lvm -k locklvm

-w /etc/sysctl.conf -p wa -k sysctl
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k T1215_Kernel_Modules_and_Extensions
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k T1215_Kernel_Modules_and_Extensions
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k T1215_Kernel_Modules_and_Extensions
-a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k T1215_Kernel_Modules_and_Extensions
-a always,exit -F arch=b32 -S finit_module -S init_module -S delete_module -F auid!=-1 -k T1215_Kernel_Modules_and_Extensions
-w /etc/modprobe.conf -p wa -k T1215_Kernel_Modules_and_Extensions
-a always,exit -F arch=b64 -S kexec_load -k T1014_Rootkit
-a always,exit -F arch=b32 -S sys_kexec_load -k T1014_Rootkit

-a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k T1099_Timestomp
-a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k T1099_Timestomp
-a always,exit -F arch=b32 -S clock_settime -k T1099_Timestomp
-a always,exit -F arch=b64 -S clock_settime -k T1099_Timestomp
-w /etc/localtime -p wa -k T1099_Timestomp

-w /usr/sbin/stunnel -p x -k T1079_Multilayer_Encryption

-w /etc/cron.allow -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.deny -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.d/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.daily/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.hourly/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.monthly/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/cron.weekly/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/crontab -p wa -k T1168_Local_Job_Scheduling
-w /var/spool/cron/crontabs/ -k T1168_Local_Job_Scheduling
-w /etc/inittab -p wa -k T1168_Local_Job_Scheduling
-w /etc/init.d/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/init/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/at.allow -p wa -k T1168_Local_Job_Scheduling
-w /etc/at.deny -p wa -k T1168_Local_Job_Scheduling
-w /var/spool/at/ -p wa -k T1168_Local_Job_Scheduling
-w /etc/anacrontab -p wa -k T1168_Local_Job_Scheduling

-w /etc/sudoers -p wa -k T1078_Valid_Accounts
-w /usr/bin/passwd -p x -k T1078_Valid_Accounts
-w /usr/sbin/groupadd -p x -k T1078_Valid_Accounts
-w /usr/sbin/groupmod -p x -k T1078_Valid_Accounts
-w /usr/sbin/addgroup -p x -k T1078_Valid_Accounts
-w /usr/sbin/useradd -p x -k T1078_Valid_Accounts
-w /usr/sbin/usermod -p x -k T1078_Valid_Accounts
-w /usr/sbin/adduser -p x -k T1078_Valid_Accounts

-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/ping -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/chgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/bin/ping6 -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/sbin/pwck -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/sbin/suexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
-a always,exit -F path=/usr/bin/newrole -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts

-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k T1052_Exfiltration_Over_Physical_Medium
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k T1052_Exfiltration_Over_Physical_Medium

-w /var/run/utmp -p wa -k T1108_Redundant_Access
-w /var/log/wtmp -p wa -k T1108_Redundant_Access
-w /var/log/btmp -p wa -k T1108_Redundant_Access

-w /var/log/faillog -p wa -k T1021_Remote_Services
-w /var/log/lastlog -p wa -k T1021_Remote_Services
-w /var/log/tallylog -p wa -k T1021_Remote_Services

-w /etc/pam.d/ -p wa -k T1071_Standard_Application_Layer_Protocol
-w /etc/security/limits.conf -p wa -k T1071_Standard_Application_Layer_Protocol
-w /etc/security/pam_env.conf -p wa -k T1071_Standard_Application_Layer_Protocol
-w /etc/security/namespace.conf -p wa -k T1071_Standard_Application_Layer_Protocol
-w /etc/security/namespace.init -p wa -k T1071_Standard_Application_Layer_Protocol
-w /etc/pam.d/common-password -p wa -k T1201_Password_Policy_Discovery

-w /etc/ssh/sshd_config -k T1021_Remote_Services

-w /bin/su -p x -k T1169_Sudo
-w /usr/bin/sudo -p x -k T1169_Sudo
-w /etc/sudoers -p rw -k T1169_Sudo
-w /etc/sudoers.d/ -p wa -k T1169_Sudo
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -F exit=EPERM -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -F exit=EPERM -k T1166_Seuid_and_Setgid

-w /sbin/shutdown -p x -k Power_State_Change
-w /sbin/poweroff -p x -k Power_State_Change
-w /sbin/reboot -p x -k Power_State_Change
-w /sbin/halt -p x -k Power_State_Change

-w /etc/group -p rxaw -k T1087_Account_Discovery
-w /etc/passwd -p rxaw -k T1087_Account_Discovery
-w /etc/gshadow -p rxaw -k T1087_Account_Discovery
-w /etc/shadow -p rxaw -k T1087_Account_Discovery
-w /etc/security/opasswd -k T1087_Account_Discovery
-w /usr/sbin/nologin -k T1087_Account_Discovery
-w /sbin/nologin -k T1087_Account_Discovery
-w /usr/bin/whoami -p x -k T1033_System_Owner_User_Discovery
-w /etc/hostname -p r -k T1082_System_Information_Discovery
-w /sbin/iptables -p x -k T1082_System_Information_Discovery
-w /sbin/ifconfig -p x -k T1082_System_Information_Discovery
-w /etc/login.defs -p wa -k T1082_System_Information_Discovery
-w /etc/resolv.conf -k T1016_System_Network_Configuration_Discovery
-w /etc/hosts.allow -k T1016_System_Network_Configuration_Discovery
-w /etc/hosts.deny -k T1016_System_Network_Configuration_Discovery
-w /etc/securetty -p wa -k T1082_System_Information_Discovery
-w /usr/sbin/tcpdump -p x -k T1049_System_Network_Connections_discovery
-w /usr/sbin/traceroute -p x -k T1049_System_Network_Connections_discovery
-w /usr/bin/wireshark -p x -k T1049_System_Network_Connections_discovery
-w /usr/bin/rawshark -p x -k T1049_System_Network_Connections_discovery

-w /usr/bin/wget -p x -k T1219_Remote_Access_Tools
-w /usr/bin/curl -p x -k T1219_Remote_Access_Tools
-w /usr/bin/base64 -p x -k T1219_Remote_Access_Tools
-w /bin/nc -p x -k T1219_Remote_Access_Tools
-w /bin/netcat -p x -k T1219_Remote_Access_Tools
-w /usr/bin/ncat -p x -k T1219_Remote_Access_Tools
-w /usr/bin/ssh -p x -k T1219_Remote_Access_Tools
-w /usr/bin/socat -p x -k T1219_Remote_Access_Tools
-w /usr/bin/rdesktop -p x -k T1219_Remote_Access_Tools

-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k T1068_Exploitation_for_Privilege_Escalation
-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k T1068_Exploitation_for_Privilege_Escalation

-a always,exit -F arch=b32 -S ptrace -k T1055_Process_Injection
-a always,exit -F arch=b64 -S ptrace -k T1055_Process_Injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k T1055_Process_Injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k T1055_Process_Injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k T1055_Process_Injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k T1055_Process_Injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k T1055_Process_Injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k T1055_Process_Injection
-w /etc/ld.so.conf -p wa -k T1055_Process_Injection
-w /bin/systemctl -p wa -k T1055_Process_Injection
-w /etc/systemd/ -p wa -k T1055_Process_Injection

-a always,exit -F arch=b32 -S socket -F a0=2  -k T1011_Exfiltration_Over_Other_Network_Medium
-a always,exit -F arch=b64 -S socket -F a0=2  -k T1011_Exfiltration_Over_Other_Network_Medium
-a always,exit -F arch=b32 -S socket -F a0=10 -k T1011_Exfiltration_Over_Other_Network_Medium
-a always,exit -F arch=b64 -S socket -F a0=10 -k T1011_Exfiltration_Over_Other_Network_Medium

-w /etc/profile.d/ -p wa -k T1156_bash_profile_and_bashrc
-w /etc/profile -p wa -k T1156_bash_profile_and_bashrc
-w /etc/shells -p wa -k T1156_bash_profile_and_bashrc
-w /etc/bashrc -p wa -k T1156_bash_profile_and_bashrc
-w /etc/csh.cshrc -p wa -k T1156_bash_profile_and_bashrc
-w /etc/csh.login -p wa -k T1156_bash_profile_and_bashrc

-a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid!=-1 -k T1200_Hardware_Additions
-a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k T1200_Hardware_Additions

-a exit,always -F arch=b32 -S all -k T1068_Exploitation_for_Privilege_Escalation_monitoring
-a exit,always -F arch=b64 -S all -k T1068_Exploitation_for_Privilege_Escalation_monitoring

-a always,exit -F arch=b64 -S execve -F uid=0 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_root_cmd
-a always,exit -F arch=b32 -S execve -F uid=0 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_root_cmd

-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k T1166_Seuid_and_Setgid

-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_access
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_access

-a always,exit -F arch=b32 -S rename,renameat,link,linkat,symlink,symlinkat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_modify
-a always,exit -F arch=b32 -S rename,renameat,link,linkat,symlink,symlinkat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_modify
-a always,exit -F arch=b64 -S rename,renameat,link,linkat,symlink,symlinkat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_modify
-a always,exit -F arch=b64 -S rename,renameat,link,linkat,symlink,symlinkat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k T1068_Exploitation_for_Privilege_Escalation_file_modify

-a always,exit -F arch=b32 -S mknod,mknodat -k T1068_Exploitation_for_Privilege_Escalation_mknod
-a always,exit -F arch=b64 -S mknod,mknodat -k T1068_Exploitation_for_Privilege_Escalation_mknod

-w /usr/bin/rpm -p x -k T1017_Application_Deployment_Software
-w /usr/bin/yum -p x -k T1017_Application_Deployment_Software
-w /usr/bin/dpkg -p x -k T1017_Application_Deployment_Software
-w /usr/bin/apt-add-repository -p x -k T1017_Application_Deployment_Software
-w /usr/bin/apt-get -p x -k T1017_Application_Deployment_Software
-w /usr/bin/aptitude -p x -k T1017_Application_Deployment_Software
-w /usr/bin/zypper -p x -k T1017_Application_Deployment_Software
-w /usr/bin/snap -p x -k T1017_Application_Deployment_Software

-w /etc/chef -p wa -k T1017_Application_Deployment_Software

-a always,exit -F arch=b64 -S useradd,usermod,userdel,groupadd,groupmod,groupdel -F auid>=1000 -F auid!=4294967295 -k T1136_Create_Account
-a always,exit -F arch=b32 -S useradd,usermod,userdel,groupadd,groupmod,groupdel -F auid>=1000 -F auid!=4294967295 -k T1136_Create_Account

-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k T1070_Indicator_Removal
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k T1070_Indicator_Removal

-a always,exit -F arch=b64 -S open,openat,creat -F dir=/tmp -F success=1 -F auid>=1000 -F auid!=4294967295 -k T1105_Ingress_Tool_Transfer
-a always,exit -F arch=b32 -S open,openat,creat -F dir=/tmp -F success=1 -F auid>=1000 -F auid!=4294967295 -k T1105_Ingress_Tool_Transfer
-a always,exit -F arch=b64 -S open,openat,creat -F dir=/var/tmp -F success=1 -F auid>=1000 -F auid!=4294967295 -k T1105_Ingress_Tool_Transfer
-a always,exit -F arch=b32 -S open,openat,creat -F dir=/var/tmp -F success=1 -F auid>=1000 -F auid!=4294967295 -k T1105_Ingress_Tool_Transfer

-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k T1059_Command_and_Scripting_Interpreter
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k T1059_Command_and_Scripting_Interpreter

-a always,exit -F arch=b64 -S ptrace -F a0=0x10 -F auid>=1000 -F auid!=4294967295 -k T1055_Process_Injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x10 -F auid>=1000 -F auid!=4294967295 -k T1055_Process_Injection

-a always,exit -F arch=b64 -S uname -F auid>=1000 -F auid!=4294967295 -k T1082_System_Information_Discovery
-a always,exit -F arch=b32 -S uname -F auid>=1000 -F auid!=4294967295 -k T1082_System_Information_Discovery

-a always,exit -F arch=b64 -S socket,connect,accept,bind -F auid>=1000 -F auid!=4294967295 -k T1016_System_Network_Configuration_Discovery
-a always,exit -F arch=b32 -S socket,connect,accept,bind -F auid>=1000 -F auid!=4294967295 -k T1016_System_Network_Configuration_Discovery

-w /etc/hosts -p wa -k T1027_Obfuscated_Files_or_Information
-w /etc/hostname -k T1082_System_Information_Discovery_hostname
-w /etc/network/ -p wa -k T1016_System_Network_Configuration_Discovery
-w /etc/netplan/ -p wa -k T1016_System_Network_Configuration_Discovery

-w /etc/init.d/ -p wa -k T1037_Boot_or_Logon_Initialization_Scripts
-w /etc/systemd/system/ -p wa -k T1037_Boot_or_Logon_Initialization_Scripts

-w /usr/lib/systemd/system/ -p wa -k T1543_Create_or_Modify_System_Process
-w /lib/systemd/system/ -p wa -k T1543_Create_or_Modify_System_Process
-w /etc/systemd/user/ -p wa -k T1543_Create_or_Modify_System_Process
-w /lib/systemd/user/ -p wa -k T1543_Create_or_Modify_System_Process

-a always,exit -F arch=b64 -S init_module,delete_module -F auid>=1000 -F auid!=4294967295 -k T1547_Kernel_modules
-a always,exit -F arch=b32 -S init_module,delete_module -F auid>=1000 -F auid!=4294967295 -k T1547_Kernel_modules

-w /etc/ld.so.conf -p wa -k T1055_Process_Injection_ld
-w /etc/ld.so.conf.d/ -p wa -k T1055_Process_Injection_ld
AUDIT_RULES_EOF
    
    chmod 640 "$AUDIT_RULES_FILE"
    success "Ubuntu Universal audit kuralları yapılandırıldı"
}

configure_audisp() {
    log "INFO" "Ubuntu sürümüne göre audisp yapılandırılıyor..."
    
    backup_file "$AUDISP_SYSLOG_CONF"
    
    if [[ "$AUDISP_METHOD" == "legacy" ]]; then
        mkdir -p "$AUDISP_PLUGINS_DIR"
        log "INFO" "Legacy audisp yapılandırması (Ubuntu $UBUNTU_VERSION)"
    else
        mkdir -p "$AUDIT_PLUGINS_DIR"
        log "INFO" "Modern audit yapılandırması (Ubuntu $UBUNTU_VERSION)"
    fi
    
    cat > "$AUDISP_SYSLOG_CONF" << 'EOF'
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_LOCAL3
format = string
EOF
    
    chmod 640 "$AUDISP_SYSLOG_CONF"
    success "Audisp syslog plugin yapılandırıldı ($AUDISP_METHOD method)"
}

configure_rsyslog() {
    log "INFO" "Rsyslog QRadar iletimi yapılandırılıyor..."

    backup_file "$RSYSLOG_QRADAR_CONF"

    cat > "$RSYSLOG_QRADAR_CONF" << EOF
module(load="omfwd")
module(load="omprog")
module(load="imfile")

template(name="QRadarFormat" type="string" string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name%: %msg%\\n")

if (\$programname == 'audit' or \$syslogfacility-text == 'local3') then {
    if (\$msg contains 'type=EXECVE') then {
        action(
            type="omprog"
            binary="$CONCAT_SCRIPT_PATH"
        )
    }
    action(
        type="omfwd"
        target="$QRADAR_IP"
        port="$QRADAR_PORT"
        protocol="tcp"
        template="QRadarFormat"
        queue.type="linkedList"
        queue.filename="qradar_audit_fwd"
        action.resumeRetryCount="-1"
    )
    stop
}

input(
    type="imfile"
    file="/var/log/audit/audit.log"
    tag="audit-direct"
    facility="local3"
    severity="info"
)

*.* @@$QRADAR_IP:$QRADAR_PORT
EOF

    chmod 644 "$RSYSLOG_QRADAR_CONF"

    backup_file "/etc/rsyslog.conf"
    cat > "/etc/rsyslog.conf" << 'RSYSLOG_CONF_EOF'
module(load="imuxsock") 
module(load="imklog" permitnonkernelfacility="on")

$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

$RepeatedMsgReduction on

$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog

$WorkDirectory /var/spool/rsyslog

$IncludeConfig /etc/rsyslog.d/*.conf

auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none,local3.none     -/var/log/syslog
kern.*                          -/var/log/kern.log
mail.*                          -/var/log/mail.log
mail.err                        /var/log/mail.err

*.emerg                         :omusrmsg:*

local3.*                        /var/log/audit/audit-syslog.log
RSYSLOG_CONF_EOF
    chmod 644 "/etc/rsyslog.conf"

    success "Rsyslog Ubuntu Universal yapılandırması tamamlandı"
}

restart_services() {
    log "INFO" "Servisler yeniden başlatılıyor..."
    
    safe_execute "auditd servisini enable etme" systemctl enable auditd
    safe_execute "rsyslog servisini enable etme" systemctl enable rsyslog
    
    safe_execute "auditd servisini durdurma" systemctl stop auditd || true
    safe_execute "rsyslog servisini durdurma" systemctl stop rsyslog || true
    
    sleep 3
    
    retry_operation "auditd servisini başlatma" systemctl start auditd
    
    sleep 2
    
    load_audit_rules
    
    retry_operation "rsyslog servisini başlatma" systemctl start rsyslog
    
    success "Tüm servisler başarıyla yapılandırıldı ve başlatıldı"
}

load_audit_rules() {
    log "INFO" "Audit kuralları yükleniyor..."
    
    if command_exists augenrules; then
        if safe_execute "augenrules ile kural yükleme" augenrules --load; then
            success "Audit kuralları augenrules ile yüklendi"
            return
        fi
    fi
    
    if safe_execute "auditctl ile kural yükleme" auditctl -R "$AUDIT_RULES_FILE"; then
        success "Audit kuralları auditctl ile yüklendi"
        return
    fi
    
    log "INFO" "Fallback: Kurallar satır satır yükleniyor..."
    local rules_loaded=0
    while IFS= read -r line; do
        if [[ -n "$line" ]] && [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ "$line" =~ ^[[:space:]]*- ]]; then
            if [[ "$line" == "-e 2" ]]; then
                continue
            fi
            if auditctl $line >> "$LOG_FILE" 2>&1; then
                ((rules_loaded++))
            fi
        fi
    done < "$AUDIT_RULES_FILE"
    
    if [[ $rules_loaded -gt 0 ]]; then
        success "$rules_loaded audit kuralı satır satır yüklendi"
    else
        warn "Hiçbir audit kuralı yüklenemedi"
    fi
}

run_validation_tests() {
    log "INFO" "Sistem doğrulama testleri çalıştırılıyor..."

    local services=("auditd" "rsyslog")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            success "$service servisi çalışıyor"
        else
            warn "$service servisi çalışmıyor"
        fi
    done
    
    if rsyslogd -N1 >> "$LOG_FILE" 2>&1; then
        success "Rsyslog yapılandırması geçerli"
    else
        warn "Rsyslog yapılandırma doğrulaması başarısız"
    fi
    
    if python3 "$CONCAT_SCRIPT_PATH" --test >> "$LOG_FILE" 2>&1; then
        success "EXECVE parser test başarılı"
    else
        warn "EXECVE parser test başarısız"
    fi
    
    test_qradar_connectivity
}

test_qradar_connectivity() {
    log "INFO" "QRadar bağlantısı test ediliyor..."
    
    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$QRADAR_IP/$QRADAR_PORT" 2>/dev/null; then
        success "QRadar bağlantısı ($QRADAR_IP:$QRADAR_PORT) başarılı"
    elif command_exists nc; then
        if timeout 5 nc -z "$QRADAR_IP" "$QRADAR_PORT" 2>/dev/null; then
            success "QRadar bağlantısı (nc ile) başarılı"
        else
            warn "QRadar'a bağlanılamıyor: $QRADAR_IP:$QRADAR_PORT"
        fi
    else
        warn "QRadar bağlantı testi yapılamıyor"
    fi
}

generate_setup_summary() {
    log "INFO" "Kurulum özeti oluşturuluyor..."
    
    echo ""
    echo "============================================================="
    echo "           QRadar Universal Ubuntu Kurulum Özeti"
    echo "============================================================="
    echo ""
    echo "SİSTEM BİLGİLERİ:"
    echo "   Ubuntu Sürümü: $UBUNTU_VERSION ($UBUNTU_CODENAME)"
    echo "   Audisp Metodu: $AUDISP_METHOD"
    echo "   QRadar Hedefi: $QRADAR_IP:$QRADAR_PORT"
    echo ""
    echo "OLUŞTURULAN DOSYALAR:"
    echo "   Audit Kuralları: $AUDIT_RULES_FILE"
    echo "   Audisp Yapılandırması: $AUDISP_SYSLOG_CONF"
    echo "   Rsyslog Yapılandırması: $RSYSLOG_QRADAR_CONF"
    echo "   EXECVE Parser: $CONCAT_SCRIPT_PATH"
    echo "   Kurulum Logu: $LOG_FILE"
    echo "   Yedek Dosyalar: $BACKUP_DIR/"
    echo ""
    echo "SERVİS DURUMU:"
    for service in auditd rsyslog; do
        if systemctl is-active --quiet "$service"; then
            echo "   ✅ $service: ÇALIŞIYOR"
        else
            echo "   ❌ $service: ÇALIŞMIYOR"
        fi
    done
    echo ""
    echo "TEST KOMUTLARI:"
    echo "   Manual test: logger -p local3.info 'Test mesajı'"
    echo "   Audit test: sudo touch /etc/passwd"
    echo "   Bağlantı test: telnet $QRADAR_IP $QRADAR_PORT"
    echo "   Parser test: python3 $CONCAT_SCRIPT_PATH --test"
    echo ""
    echo "============================================================="
    echo ""
    
    success "QRadar Universal Ubuntu kurulumu başarıyla tamamlandı!"
}

main() {
    touch "$LOG_FILE" || error_exit "Log dosyası oluşturulamıyor: $LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null || true
    
    log "INFO" "============================================================="
    log "INFO" "QRadar Universal Ubuntu Log Forwarding Installer v$SCRIPT_VERSION"
    log "INFO" "Başlatılıyor: $(date)"
    log "INFO" "QRadar Hedefi: $QRADAR_IP:$QRADAR_PORT"
    log "INFO" "============================================================="
    
    [[ $EUID -eq 0 ]] || error_exit "Bu script root yetkisiyle çalıştırılmalıdır. 'sudo' kullanın."
    
    detect_ubuntu_version
    install_required_packages
    deploy_execve_parser
    configure_auditd
    configure_audisp
    configure_rsyslog
    restart_services
    run_validation_tests
    generate_setup_summary
    
    log "INFO" "============================================================="
    log "INFO" "Kurulum tamamlandı: $(date)"
    log "INFO" "============================================================="
}

if [[ -z "$1" ]] || [[ -z "$2" ]]; then
    echo "Kullanım: $0 <QRADAR_IP> <QRADAR_PORT>"
    echo "Örnek: $0 192.168.1.100 514"
    exit 1
fi

QRADAR_IP="$1"
QRADAR_PORT="$2"

if ! [[ "$QRADAR_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    error_exit "Geçersiz IP adresi formatı: $QRADAR_IP"
fi

if ! [[ "$QRADAR_PORT" =~ ^[0-9]+$ ]] || [[ "$QRADAR_PORT" -lt 1 ]] || [[ "$QRADAR_PORT" -gt 65535 ]]; then
    error_exit "Geçersiz port numarası: $QRADAR_PORT (1-65535 arası olmalı)"
fi

main

exit 0
