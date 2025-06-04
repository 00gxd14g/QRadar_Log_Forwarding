#!/usr/bin/env python3
import sys
import re

def process_line(line):
    # Only process EXECVE messages
    if "type=EXECVE" not in line:
        return line

    # Find all argument fields: a0="...", a1="...", etc.
    # Regex improved to handle empty arguments like a1=""
    args = re.findall(r'a\d+="([^"]*)"', line)

    if args:
        # Combine all found arguments with a space
        combined_command = " ".join(args)
        # Escape double quotes within the combined command to prevent breaking the log format
        escaped_combined_command = combined_command.replace('"', '\\"')

        # Remove all existing aX="..." fields from the line
        # and any trailing space.
        new_line = re.sub(r'a\d+="(?:[^"\\]|\\.)*"\s*', '', line).strip()

        # Append a single a0 field with the combined command
        # Ensure there's a space before adding a0 if new_line is not empty
        if new_line and not new_line.endswith(" "):
            new_line += " "
        new_line += 'a0="' + escaped_combined_command + '"'
        # Adding a prefix for easier debugging/identification if needed, e.g., "MODIFIED_EXECVE: "
        # For now, keeping it clean as per typical log requirements.
        # If you want the "MODIFIED:" prefix, uncomment the next line and comment out the one after.
        # return "MODIFIED: " + new_line
        return new_line


    return line # Return original line if no args found or not EXECVE

def main():
    try:
        for line_in in sys.stdin:
            processed_line = process_line(line_in.strip())
            print(processed_line)
            sys.stdout.flush() # Ensure output is sent immediately
    except Exception as e:
        # Log errors to stderr for visibility by rsyslog's omprog
        print(f"concat_execve.py ERROR: {e}", file=sys.stderr)
        # Optionally, could print the original line to stdout to avoid data loss
        # if 'line_in' in locals(): print(line_in.strip())

if __name__ == '__main__':
    main()
