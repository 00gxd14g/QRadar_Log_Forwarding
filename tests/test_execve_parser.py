import sys
import os
import pytest
import re

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src/helpers"))
)

from execve_parser import ExecveParser


@pytest.fixture
def parser():
    return ExecveParser()


def get_user_info(line):
    info = {}
    for key in ["auid", "uid", "gid"]:
        match = re.search(rf"\b{key}=(\d+)", line)
        if match:
            num_id = int(match.group(1))
            if num_id == 4294967295:  # Unset ID (-1)
                continue
            try:
                if "uid" in key:
                    info[f"{key}_name"] = "testuser"
                elif "gid" in key:
                    info[f"{key}_name"] = "testgroup"
            except (KeyError, ValueError):
                pass  # Ignore if ID does not exist
    return info


def test_parse_line(parser, monkeypatch):
    monkeypatch.setattr(parser, "_get_user_info", get_user_info)
    line = 'type=EXECVE msg=audit(1678886400.123:456): auid=1000 uid=1000 gid=1000 argc=3 a0="sudo" a1="ls" a2="-la"'

    parsed_line = parser.parse_line(line)

    assert 'cmd="sudo ls -la"' in parsed_line


def test_parse_line_no_args(parser, monkeypatch):
    monkeypatch.setattr(parser, "_get_user_info", get_user_info)
    line = 'type=EXECVE msg=audit(1678886400.123:456): auid=1000 uid=1000 gid=1000 argc=1 a0="ls"'

    parsed_line = parser.parse_line(line)

    assert 'cmd="ls"' in parsed_line


def test_parse_line_no_type_execve(parser):
    line = "type=SYSCALL msg=audit(1678886400.123:456):"
    assert parser.parse_line(line) == line


def test_parse_line_proctitle(parser):
    line = 'type=EXECVE msg=audit(1678886400.123:456): proctitle="/bin/bash"'
    assert parser.parse_line(line) == line
