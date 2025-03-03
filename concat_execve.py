#!/usr/bin/env python3
import sys
import re

def process_line(line):
    # Check if the line contains an EXECVE message
    if "type=EXECVE" not in line:
        return line
    # Find all argument fields: a0="...", a1="...", etc.
    args = re.findall(r'a\d+="([^"]+)"', line)
    if args:
        # Combine all found arguments with a space
        combined_command = " ".join(args)
        # Remove all existing aX="..." fields from the line
        new_line = re.sub(r'(a\d+="[^"]+"\s*)+', '', line)
        # Append a single a0 field with the combined command
        new_line = new_line.strip() + ' a0="' + combined_command + '"'
        return "MODIFIED " + new_line
    return line

def main():
    for line in sys.stdin:
        processed_line = process_line(line.strip())
        print(processed_line)

if __name__ == '__main__':
    main()
