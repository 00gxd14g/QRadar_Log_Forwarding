---
name: Bug report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
assignees: ''
---

## 🐛 Bug Description

A clear and concise description of what the bug is.

## 🔄 Steps to Reproduce

1. Go to '...'
2. Run command '...'
3. See error

## ✅ Expected Behavior

A clear and concise description of what you expected to happen.

## ❌ Actual Behavior

A clear and concise description of what actually happened.

## 🖥️ Environment

**Operating System:**
- [ ] Ubuntu (version: )
- [ ] Debian (version: )
- [ ] RHEL (version: )
- [ ] CentOS (version: )
- [ ] Other: 

**Script Version:**
- QRadar Log Forwarding version: [e.g. v3.0.0]

**System Details:**
- Kernel version: [output of `uname -r`]
- Package manager: [apt/yum/dnf]
- SELinux status: [enabled/disabled/permissive]

## 📋 Configuration

**QRadar Settings:**
- QRadar IP: [redacted]
- QRadar Port: [e.g. 514]

**Services Status:**
```bash
# Output of: sudo systemctl status auditd rsyslog
```

## 📝 Log Output

**Setup Log (`/var/log/qradar_setup.log`):**
```
[Paste relevant log entries here]
```

**System Logs:**
```bash
# Output of: sudo journalctl -u auditd -u rsyslog --since "1 hour ago"
```

**Error Messages:**
```
[Paste any error messages here]
```

## 🔍 Troubleshooting Attempted

- [ ] Checked service status (`systemctl status auditd rsyslog`)
- [ ] Verified network connectivity to QRadar
- [ ] Reviewed setup logs
- [ ] Tested with different QRadar settings
- [ ] Ran script diagnostics
- [ ] Other: 

## 📎 Additional Context

Add any other context about the problem here.

## 🔧 Workaround

If you found a temporary workaround, please describe it here.