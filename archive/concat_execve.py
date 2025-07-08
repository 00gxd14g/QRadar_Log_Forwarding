#!/usr/bin/env python3
"""
QRadar EXECVE Command Concatenation Script

This script processes audit EXECVE messages and concatenates
command arguments into a single field for better SIEM parsing.

Features:
- Processes EXECVE audit log entries
- Concatenates command arguments (a0, a1, a2, ...) into a single command field
- Handles argument ordering correctly
- Provides error handling and logging
- Outputs in a format optimized for QRadar parsing

Author: QRadar Log Forwarding Project
Version: 2.0
"""

import sys
import re
import json
from datetime import datetime
import logging

# Configure logging for debugging
logging.basicConfig(
    level=logging.WARNING,  # Only log warnings and errors to avoid cluttering syslog
    format='%(asctime)s - concat_execve - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)

def extract_execve_args(line):
    """
    Extract EXECVE arguments from audit log line.
    Returns list of tuples (index, argument) sorted by index.
    """
    # Match aX="argument" patterns, handling escaped quotes
    pattern = r'a(\d+)="([^"]*(?:\\.[^"]*)*)"'
    matches = re.findall(pattern, line)
    
    if not matches:
        return []
    
    # Convert to list of (int_index, argument) and sort by index
    args_with_index = [(int(idx), arg) for idx, arg in matches]
    args_with_index.sort(key=lambda x: x[0])
    
    return args_with_index

def clean_argument(arg):
    """
    Clean and unescape argument strings.
    """
    # Unescape common escape sequences
    arg = arg.replace('\\"', '"')
    arg = arg.replace('\\\\', '\\')
    arg = arg.replace('\\n', '\n')
    arg = arg.replace('\\t', '\t')
    return arg

def process_execve_line(line):
    """
    Process a single EXECVE audit log line.
    """
    if "type=EXECVE" not in line:
        return line
    
    try:
        # Extract arguments
        args_with_index = extract_execve_args(line)
        
        if not args_with_index:
            logging.debug("No arguments found in EXECVE line")
            return line
        
        # Clean and combine arguments
        cleaned_args = [clean_argument(arg) for _, arg in args_with_index]
        combined_command = " ".join(cleaned_args)
        
        # Remove all existing aX="..." fields from the line
        cleaned_line = re.sub(r'a\d+="[^"]*(?:\\.[^"]*)*"\s*', '', line)
        cleaned_line = cleaned_line.strip()
        
        # Add combined command as single field
        if cleaned_line and not cleaned_line.endswith(' '):
            cleaned_line += ' '
        
        # Escape quotes in combined command
        escaped_command = combined_command.replace('"', '\\"')
        processed_line = f'{cleaned_line}cmd="{escaped_command}"'
        
        logging.debug(f"Processed EXECVE: {len(args_with_index)} args -> {len(combined_command)} chars")
        return f"PROCESSED: {processed_line}"
        
    except Exception as e:
        logging.error(f"Error processing EXECVE line: {e}")
        return line

def validate_line(line):
    """
    Validate that a line is properly formatted.
    """
    if not line or not line.strip():
        return False
    
    # Basic audit log format validation
    if not re.search(r'type=\w+', line):
        return False
    
    return True

def main():
    """
    Main processing loop - reads from stdin and processes each line.
    """
    # Handle test mode
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        test_function()
        return
    
    processed_count = 0
    error_count = 0
    
    try:
        for line_number, line in enumerate(sys.stdin, 1):
            line = line.strip()
            
            if not line:
                continue
            
            if not validate_line(line):
                logging.warning(f"Line {line_number}: Invalid format, skipping")
                print(line, flush=True)
                continue
            
            try:
                processed_line = process_execve_line(line)
                print(processed_line, flush=True)
                
                if "PROCESSED:" in processed_line:
                    processed_count += 1
                    
            except Exception as e:
                logging.error(f"Line {line_number}: Processing error - {e}")
                print(line, flush=True)  # Output original line on error
                error_count += 1
        
        # Log final statistics to stderr (won't go to syslog)
        if processed_count > 0 or error_count > 0:
            logging.info(f"Processing complete: {processed_count} processed, {error_count} errors")
            
    except KeyboardInterrupt:
        logging.info("Processing interrupted by user")
        sys.exit(0)
    except BrokenPipeError:
        # Handle broken pipe gracefully (common when piping to other commands)
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error in main processing loop: {e}")
        sys.exit(1)

def test_function():
    """
    Test function for validating script functionality.
    Can be called with --test argument for debugging.
    """
    test_lines = [
        'type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="ls" a1="-la" a2="/tmp"',
        'type=EXECVE msg=audit(1234567890.124:457): argc=2 a0="cat" a1="/etc/passwd"',
        'type=EXECVE msg=audit(1234567890.125:458): argc=1 a0="whoami"',
        'type=SYSCALL msg=audit(1234567890.126:459): arch=c000003e syscall=2 success=yes',
        'type=EXECVE msg=audit(1234567890.127:460): argc=4 a0="sudo" a1="-u" a2="root" a3="id"'
    ]
    
    print("=== CONCAT_EXECVE SCRIPT TEST ===")
    print(f"Testing {len(test_lines)} sample lines...")
    print()
    
    for i, line in enumerate(test_lines, 1):
        print(f"Test {i}:")
        print(f"  Input:  {line}")
        result = process_execve_line(line)
        print(f"  Output: {result}")
        print()
    
    print("Test completed successfully!")

if __name__ == "__main__":
    main()