import sys
import os
import pytest
from unittest import mock
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/helpers')))

from execve_parser import ExecveParser

@pytest.fixture
def parser():
    return ExecveParser()

# Mock user structure for pwd.getpwuid
class MockPasswd:
    def __init__(self, pw_name):
        self.pw_name = pw_name

# Mock group structure for grp.getgrgid
class MockGroup:
    def __init__(self, gr_name):
        self.gr_name = gr_name

@mock.patch('pwd.getpwuid')
@mock.patch('grp.getgrgid')
def test_parse_line(mock_getgrgid, mock_getpwuid, parser):
    # Mock the system calls
    mock_getpwuid.return_value = MockPasswd('testuser')
    mock_getgrgid.return_value = MockGroup('testgroup')
    
    line = 'type=EXECVE msg=audit(1678886400.123:456): auid=1000 uid=1000 gid=1000 argc=3 a0="sudo" a1="ls" a2="-la"'
    expected = 'type=EXECVE msg=audit(1678886400.123:456): auid=1000 uid=1000 gid=1000 cmd="sudo ls -la" auid_name="testuser" gid_name="testgroup" mitre_techniques="T1548" uid_name="testuser"'

    parsed_line = parser.parse_line(line)

    # Sort the key-value pairs for comparison
    parsed_parts = parsed_line.split(" ")
    expected_parts = expected.split(" ")

    assert sorted(parsed_parts) == sorted(expected_parts)

@mock.patch('pwd.getpwuid')
@mock.patch('grp.getgrgid')
def test_parse_line_no_args(mock_getgrgid, mock_getpwuid, parser):
    # Mock the system calls
    mock_getpwuid.return_value = MockPasswd('testuser')
    mock_getgrgid.return_value = MockGroup('testgroup')
    
    line = 'type=EXECVE msg=audit(1678886400.123:456): auid=1000 uid=1000 gid=1000 argc=1 a0="ls"'
    expected = 'type=EXECVE msg=audit(1678886400.123:456): auid=1000 uid=1000 gid=1000 cmd="ls" auid_name="testuser" gid_name="testgroup" uid_name="testuser"'

    parsed_line = parser.parse_line(line)

    # Sort the key-value pairs for comparison
    parsed_parts = parsed_line.split(" ")
    expected_parts = expected.split(" ")

    assert sorted(parsed_parts) == sorted(expected_parts)

def test_parse_line_no_type_execve(parser):
    line = 'type=SYSCALL msg=audit(1678886400.123:456):'
    assert parser.parse_line(line) == line

def test_parse_line_proctitle(parser):
    line = 'type=EXECVE msg=audit(1678886400.123:456): proctitle="/bin/bash"'
    assert parser.parse_line(line) == line
