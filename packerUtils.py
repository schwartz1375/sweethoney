#!/usr/bin/env python3

__author__ = 'Matthew Schwartz (@schwartz1375)'
__version__ = '0.5'

import os
import subprocess

from termcolor import cprint


def get_packer_info(file_path, diec_path):
    # Check if diec_path is a valid file
    if not os.path.isfile(diec_path):
        cprint(f"Error: {diec_path} does not exist or is not a file", "red")
        return None

    # Check if diec_path is executable
    if not os.access(diec_path, os.X_OK):
        cprint(f"Error: {diec_path} is not executable", "red")
        return None

    # Command to run DiE on the file
    cmd = [diec_path, file_path]

    # Run the command and capture the output
    result = subprocess.run(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    # Check for errors
    if result.returncode != 0:
        cprint(f"Error running DiE: {result.stderr.decode()}", "red")
        return None

    # Parse the packer information from the output
    output = result.stdout.decode()
    packer_info = parse_packer_info(output)

    return packer_info


def parse_packer_info(die_output):
    # Split the output into lines, strip leading and trailing whitespace from each line,
    # exclude empty lines, and then join the remaining lines with " | "
    single_line_output = ' | '.join(line.strip() for line in die_output.split('\n') if line.strip())
    
    return single_line_output



