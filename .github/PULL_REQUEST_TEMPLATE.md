# Pull Request

## 📋 Description

Brief description of the changes in this PR.

## 🔄 Type of Change

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🧹 Code cleanup/refactoring
- [ ] ⚡ Performance improvement
- [ ] 🔒 Security fix

## 🧪 Testing

**Test Environment:**
- [ ] Ubuntu 20.04/22.04/24.04
- [ ] Debian 11/12
- [ ] RHEL/CentOS 8/9
- [ ] Other: _______________

**Testing Performed:**
- [ ] Script syntax validation (`bash -n`)
- [ ] Python syntax validation (`python3 -m py_compile`)
- [ ] Functionality testing (`--test` flag)
- [ ] Integration testing with QRadar
- [ ] Manual testing on target distribution(s)
- [ ] Edge case testing

**Test Results:**
```bash
# Paste test output here
```

## 📋 Checklist

**Code Quality:**
- [ ] Code follows existing style and conventions
- [ ] No hardcoded values (IP addresses, passwords, etc.)
- [ ] Error handling is appropriate
- [ ] Logging is consistent with existing patterns
- [ ] Comments added for complex logic

**Documentation:**
- [ ] README.md updated if needed
- [ ] CHANGELOG.md updated with changes
- [ ] Inline code comments added where necessary
- [ ] Function/script headers updated

**Compatibility:**
- [ ] Backward compatible with existing installations
- [ ] Works on all supported Linux distributions
- [ ] No breaking changes to configuration files
- [ ] Existing audit rules preserved or properly migrated

**Security:**
- [ ] No security vulnerabilities introduced
- [ ] File permissions set correctly
- [ ] Input validation implemented where needed
- [ ] No sensitive information in logs

## 🔄 Related Issues

Fixes #(issue number)
Related to #(issue number)

## 🖼️ Screenshots/Logs (if applicable)

```bash
# Paste relevant logs or screenshots here
```

## 🔍 Additional Notes

Any additional information that reviewers should know about this PR.

## 📋 Deployment Notes

Any special considerations for deployment:
- Configuration changes required
- Service restarts needed
- Migration steps
- Rollback procedures