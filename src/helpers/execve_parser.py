#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QRadar Unified EXECVE Parser

This script processes and enriches audit EXECVE messages for optimal SIEM analysis.
It combines multi-part arguments, maps commands to MITRE ATT&CK techniques,
and enriches logs with human-readable user and group names.

Version: 1.0.0
Author: Gemini
"""

import sys
import re
import pwd
import grp
import signal
from typing import Dict, List, Tuple, Optional

# --- MITRE ATT&CK Technique Mappings ---
# A curated dictionary mapping techniques to common Linux commands and patterns.
MITRE_TECHNIQUES: Dict[str, List[str]] = {
    # T1003: OS Credential Dumping
    'T1003': ['cat /etc/shadow', 'cat /etc/gshadow', 'getent shadow', 'dump'],
    # T1059: Command and Scripting Interpreter
    'T1059': ['bash', 'sh', 'zsh', 'python', 'perl', 'ruby', 'php', 'node'],
    # T1070: Indicator Removal on Host
    'T1070': ['history -c', 'rm /root/.bash_history', 'shred', 'wipe'],
    # T1071: Application Layer Protocol (e.g., for C2)
    'T1071': ['curl', 'wget', 'ftp', 'sftp'],
    # T1082: System Information Discovery
    'T1082': ['uname -a', 'lscpu', 'lshw', 'dmidecode'],
    # T1087: Account Discovery
    'T1087': ['who', 'w', 'last', 'lastlog', 'id', 'getent passwd'],
    # T1105: Ingress Tool Transfer
    'T1105': ['scp', 'rsync', 'socat', 'ncat'],
    # T1548: Abuse Elevation Control Mechanism
    'T1548': ['sudo', 'su -', 'pkexec'],
    # T1562: Impair Defenses
    'T1562': ['systemctl stop auditd', 'service auditd stop', 'auditctl -e 0', 'setenforce 0'],
}

class ExecveParser:
    """
    Parses, enriches, and formats audit log lines, focusing on EXECVE events.
    """

    def __init__(self):
        """Initializes patterns and signal handlers for graceful shutdown."""
        self.execve_pattern = re.compile(r'type=EXECVE')
        self.arg_pattern = re.compile(r'a(\d+)="([^"]*)"')
        self.hex_arg_pattern = re.compile(r'a\d+=([0-9A-Fa-f]+)')
        self.user_pattern = re.compile(r'\b(a?uid|gid)=(\d+)')
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum: int, frame) -> None:
        """Handles termination signals to exit gracefully."""
        sys.exit(0)

    def _get_user_info(self, line: str) -> Dict[str, str]:
        """Extracts and resolves user/group IDs from the log line."""
        info = {}
        matches = self.user_pattern.findall(line)
        for key, value in matches:
            try:
                num_id = int(value)
                if num_id == 4294967295:  # Unset ID (-1)
                    continue
                
                if 'uid' in key:
                    user_name = pwd.getpwuid(num_id).pw_name
                    info[f'{key}_name'] = user_name
                elif 'gid' in key:
                    group_name = grp.getgrgid(num_id).gr_name
                    info[f'{key}_name'] = group_name
            except (KeyError, ValueError):
                # Ignore if ID does not exist
                pass
        return info

    def _analyze_mitre_techniques(self, command: str) -> List[str]:
        """Matches a command against the MITRE ATT&CK knowledge base."""
        techniques_found = []
        for tech_id, patterns in MITRE_TECHNIQUES.items():
            for pattern in patterns:
                if pattern in command:
                    techniques_found.append(tech_id)
                    break  # Move to the next technique once one pattern matches
        return techniques_found

    def _format_kv(self, data: Dict[str, str]) -> str:
        """Formats a dictionary into a key="value" string."""
        return ' '.join([f'{key}="{value}"' for key, value in data.items()])

    def parse_line(self, line: str) -> Optional[str]:
        """
        Processes a single log line. If it's an EXECVE event, it reconstructs
        the command and enriches the log. Otherwise, it returns the line as is.
        """
        if not self.execve_pattern.search(line):
            return line

        try:
            # 1. Reconstruct the full command
            args: Dict[int, str] = {}
            # First, get all normally quoted arguments
            for match in self.arg_pattern.finditer(line):
                args[int(match.group(1))] = match.group(2)
            # Then, get any hex-encoded arguments that might have been missed
            for match in self.hex_arg_pattern.finditer(line):
                key, hex_val = match.group(0).split('=', 1)
                arg_num = int(key[1:])
                if arg_num not in args:
                    try:
                        args[arg_num] = bytes.fromhex(hex_val).decode('utf-8', 'replace')
                    except ValueError:
                        pass # Ignore non-hex values

            if not args:
                return line # Nothing to parse

            full_command = " ".join(args[i] for i in sorted(args.keys()))

            # 2. Clean the original line by removing argument fields
            line = self.arg_pattern.sub('', line)
            line = self.hex_arg_pattern.sub('', line)
            line = re.sub(r'argc=\d+\s*', '', line).strip()

            # 3. Enrich the log line
            enrichment_data = {
                'cmd': full_command,
            }
            
            # Add user/group names
            user_info = self._get_user_info(line)
            enrichment_data.update(user_info)

            # Add MITRE techniques
            mitre_info = self._analyze_mitre_techniques(full_command)
            if mitre_info:
                enrichment_data['mitre_techniques'] = ",".join(sorted(list(set(mitre_info))))

            return f"{line} {self._format_kv(enrichment_data)}"

        except Exception:
            # In case of any error, return the original line to prevent data loss
            return line

    def run(self) -> None:
        """
        Main processing loop. Reads from stdin, processes each line,
        and prints the result to stdout.
        """
        try:
            for line in sys.stdin:
                processed_line = self.parse_line(line.strip())
                if processed_line:
                    print(processed_line, flush=True)
        except (IOError, BrokenPipeError):
            # Gracefully exit on broken pipe (e.g., rsyslog restarts)
            sys.exit(0)
        except Exception:
            # Exit on any other fatal error
            sys.exit(1)

if __name__ == "__main__":
    parser = ExecveParser()
    parser.run()
