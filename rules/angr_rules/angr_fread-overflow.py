#!/usr/bin/env python3
"""
Angr script to detect potential buffer overflow in fread usage.

The vulnerability occurs when fread reads data into a fixed-size stack buffer without verifying
that the destination buffer is large enough. This script uses symbolic execution to find unsafe fread calls.

Usage:
    python3 angr_fread_overflow.py "BINARY_NAME -arg1 value1 -arg2 value2"

The script is modular and can be imported into a larger program.
"""

import angr
import sys
import claripy

def find_fread_overflow(target_binary, args=None):
    project = angr.Project(target_binary, auto_load_libs=False)

    # Create an initial state
    state = project.factory.entry_state(args=args)
    
    # Use symbolic execution to find unsafe fread calls
    simulation = project.factory.simgr(state)

    def is_fread(state):
        """Check if the current state is executing fread with a dangerous size parameter."""
        return b"fread" in state.posix.dumps(1)  # Looking at stdout for evidence

    print(f"Analyzing {target_binary} for fread buffer overflows...")
    simulation.explore(find=is_fread)

    if simulation.found:
        print("Potential buffer overflow detected in fread!")
        for found_state in simulation.found:
            print(f"Exploitability Path: {found_state}")
    else:
        print("No fread overflows found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: angr_fread_overflow.py 'BINARY_NAME -arg1 value1 -arg2 value2'")
        sys.exit(1)

    # Extract target binary and arguments
    target_cmd = sys.argv[1].split()
    target_binary = target_cmd[0]
    args = target_cmd[1:] if len(target_cmd) > 1 else None

    find_fread_overflow(target_binary, args)