# RHEL Compliance Notes

This document outlines the remediation actions taken to ensure the QRadar Log Forwarding scripts are compliant with RHEL standards and best practices.

## RainerScript Consistency

*   **`re_extract` instead of `regex_extract`**: The `regex_extract` function is deprecated in newer versions of rsyslog. All instances have been replaced with `re_extract` to ensure compatibility with the latest rsyslog versions.
*   **Camel-cased queue parameters**: Queue parameters have been camel-cased (e.g., `queue.dequeueBatchSize` instead of `queue.dequeuebatchsize`) to align with the latest rsyslog documentation and best practices.

## Shell Robustness

*   **`set -Eeuo pipefail` and `ERR` trap**: All Bash scripts now include `set -Eeuo pipefail` and a trap for the `ERR` signal. This ensures that the scripts will exit immediately if a command fails, preventing unexpected behavior.
*   **`eval` replaced with explicit arrays**: All instances of `eval` have been replaced with explicit arrays to prevent command injection vulnerabilities.
*   **`safe_execute` wrapper**: A `safe_execute` wrapper has been introduced to provide a consistent way of executing commands and logging the output.

## Path Resolution

*   **Absolute paths**: All relative template inclusions have been replaced with absolute paths derived from the script location. This ensures that the scripts can be run from any directory without errors.
*   **`project_root()` helper function**: A `project_root()` helper function has been added to provide a consistent way of determining the project root directory.

## CI Static Analysis

*   **ShellCheck, Black, and Ruff**: The GitHub Actions pipeline has been updated to include ShellCheck, Black, and Ruff to ensure that all code is properly formatted and free of common errors.

## Unit & Integration Tests

*   **pytest-based harness**: A pytest-based harness has been provided for every Python helper to ensure that they are properly tested.
*   **Matrix build**: A matrix build has been added to the GitHub Actions pipeline to test the scripts on RHEL 7, 8, 9 and Amazon Linux 2 using Docker images.
*   **`rsyslogd -N1` and `auditctl` checks**: The matrix build now includes checks to ensure that the rsyslog configuration is valid and that the audit rules are loaded correctly.

## Firewall Governance

*   **`--open-port` flag**: An `--open-port` flag has been added to the installer scripts to allow users to control whether the QRadar port is opened in the firewall.

## Template Safety

*   **`${var:-N/A}` syntax**: The `${var:-N/A}` syntax is now used for optional rsyslog fields to prevent errors when a field is not present.
