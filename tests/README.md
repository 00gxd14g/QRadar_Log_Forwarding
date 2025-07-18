# QRadar Log Forwarding Tests

This directory contains comprehensive tests for the QRadar Log Forwarding installers.

## Test Structure

### Docker Tests
- `docker/` - Docker-based integration tests
  - `Dockerfile.ubuntu` - Ubuntu 24.04 test container
  - `Dockerfile.debian` - Debian 12 test container  
  - `Dockerfile.rhel` - Rocky Linux 9 test container
  - `Dockerfile.universal` - Universal installer test container
  - `run_tests.sh` - Test runner script

### Python Tests
- `test_execve_parser.py` - Tests for the EXECVE parser script

## Running Tests

### Docker Tests
```bash
cd tests/docker
./run_tests.sh
```

### Individual Docker Tests
```bash
# Test Ubuntu installer
docker build -f tests/docker/Dockerfile.ubuntu -t qradar-ubuntu-test .
docker run --rm qradar-ubuntu-test

# Test Debian installer
docker build -f tests/docker/Dockerfile.debian -t qradar-debian-test .
docker run --rm qradar-debian-test

# Test RHEL installer
docker build -f tests/docker/Dockerfile.rhel -t qradar-rhel-test .
docker run --rm qradar-rhel-test

# Test Universal installer
docker build -f tests/docker/Dockerfile.universal -t qradar-universal-test .
docker run --rm qradar-universal-test
```

### Python Tests
```bash
cd tests
python test_execve_parser.py
```

### Syntax Checks
```bash
# Check all shell scripts
find . -name "*.sh" -type f | xargs shellcheck

# Check Python scripts
find . -name "*.py" -type f | xargs python -m py_compile
```

## CI/CD Integration

The tests are automatically run on every push to the main branch via GitHub Actions. The workflow includes:

1. **Syntax Check** - Validates all shell scripts and Python code
2. **Docker Tests** - Runs all installers in isolated Docker containers
3. **Configuration Validation** - Checks rsyslog configs and audit rules
4. **Release Preparation** - Creates deployment artifacts

## Test Features

- **Dry Run Mode**: All tests run in `--dry-run` mode to avoid system modifications
- **Multi-Platform**: Tests Ubuntu, Debian, and RHEL-based systems
- **Isolated Environment**: Each test runs in a clean Docker container
- **Comprehensive Coverage**: Tests syntax, configuration, and installer functionality
- **Automated Cleanup**: Old test artifacts are automatically removed

## Test Requirements

- Docker (for integration tests)
- Python 3.8+ (for Python tests)
- shellcheck (for syntax validation)
- rsyslog (for configuration validation)

## Adding New Tests

1. Create new Dockerfile in `tests/docker/` for new platforms
2. Add test configuration to `run_tests.sh`
3. Update GitHub Actions workflow in `.github/workflows/ci.yml`
4. Document test requirements in this README