import sys
import os
import pytest
import re
from unittest.mock import patch, MagicMock

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src/helpers"))
)

from execve_parser import ExecveParser


@pytest.fixture
def parser():
    """Fixture to create an ExecveParser instance for tests."""
    return ExecveParser()


def mock_get_user_info(line: str) -> dict:
    """Mock implementation of _get_user_info for consistent testing."""
    info = {}
    uid_match = re.search(r"\buid=(\d+)", line)
    if uid_match:
        info["uid_name"] = "testuser"
    gid_match = re.search(r"\bgid=(\d+)", line)
    if gid_match:
        info["gid_name"] = "testgroup"
    auid_match = re.search(r"\bauid=(\d+)", line)
    if auid_match:
        info["auid_name"] = "testuser"
    return info


@patch("execve_parser.pwd", MagicMock())
@patch("execve_parser.grp", MagicMock())
def test_parse_line_simple(parser):
    """Test parsing a simple EXECVE log line."""
    line = 'type=EXECVE msg=audit(1678886400.123:456): auid=1000 uid=1000 gid=1000 argc=3 a0="sudo" a1="ls" a2="-la"'
    parser._get_user_info = mock_get_user_info
    parsed_line = parser.parse_line(line)
    assert 'cmd="sudo ls -la"' in parsed_line
    assert 'uid_name="testuser"' in parsed_line
    assert 'gid_name="testgroup"' in parsed_line


def test_parse_line_no_args(parser):
    """Test parsing an EXECVE log line with no arguments."""
    line = 'type=EXECVE msg=audit(1678886400.123:456): auid=1000 uid=1000 gid=1000 argc=1 a0="ls"'
    parser._get_user_info = mock_get_user_info
    parsed_line = parser.parse_line(line)
    assert 'cmd="ls"' in parsed_line


def test_parse_line_non_execve(parser):
    """Test that non-EXECVE log lines are not modified."""
    line = "type=SYSCALL msg=audit(1678886400.123:456):"
    assert parser.parse_line(line) == line


def test_parse_line_with_hex_args(parser):
    """Test parsing a line with hex-encoded arguments."""
    line = 'type=EXECVE msg=audit(1678886400.123:456): argc=2 a0="echo" a1=68656c6c6f'
    parser._get_user_info = mock_get_user_info
    parsed_line = parser.parse_line(line)
    assert 'cmd="echo hello"' in parsed_line


def test_mitre_technique_analysis(parser):
    """Test the MITRE ATT&CK technique analysis."""
    line = 'type=EXECVE msg=audit(1678886400.123:456): argc=2 a0="cat" a1="/etc/shadow"'
    parser._get_user_info = mock_get_user_info
    parsed_line = parser.parse_line(line)
    assert 'mitre_techniques="T1003"' in parsed_line


def test_empty_line(parser):
    """Test that an empty line is handled gracefully."""
    assert parser.parse_line("") == ""


def test_line_with_no_args_to_parse(parser):
    """Test a line that looks like EXECVE but has no 'a' fields."""
    line = "type=EXECVE msg=audit(1678886400.123:456):"
    assert parser.parse_line(line) == line


@patch("builtins.print")
def test_run(mock_print, parser):
    """Test the main run loop of the parser."""
    input_lines = [
        'type=EXECVE msg=audit(1678886400.123:456): argc=2 a0="ls" a1="-l"\n',
        "type=SYSCALL\n",
    ]
    with patch("sys.stdin", input_lines):
        parser.run()
    assert mock_print.call_count == 2
    mock_print.assert_any_call(
        'type=EXECVE msg=audit(1678886400.123:456): cmd="ls -l"', flush=True
    )
    mock_print.assert_any_call("type=SYSCALL", flush=True)
