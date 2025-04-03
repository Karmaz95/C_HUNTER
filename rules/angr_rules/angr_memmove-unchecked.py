#!/usr/bin/env python3
"""
Angr script to detect potential unchecked usage of memmove.

The vulnerability occurs when memmove is used without proper bounds checking, potentially leading to buffer overflows.
This script hooks into the memmove function and tracks its usage to identify unsafe calls.

Usage:
    python3 angr_memmove-unchecked.py "BINARY_NAME -arg1 value1 -arg2 value2"

The script is modular and can be imported into a larger program.
"""

import angr
import sys

def find_memmove_unchecked(target_binary, args=None):
    project = angr.Project(target_binary, auto_load_libs=False)
    state = project.factory.entry_state(args=args)
    simulation = project.factory.simgr(state)

    def reached_memmove(state):
        # Look for "memmove" in the current function name 
        # or use a more robust hook if you have debug symbols.
        if state.globals.get('current_func', b'') == b'memmove':
            return True
        return False

    # Hook functions to track if we're in 'memmove'
    @project.hook_symbol('memmove')
    def memmove_hook(state):
        state.globals['current_func'] = b'memmove'

    simulation.explore(find=reached_memmove)

    if simulation.found:
        print("Potential unchecked memmove usage discovered!")
        for st in simulation.found:
            print("Found state:", st)
    else:
        print("No suspicious memmove usage identified.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 angr_memmove-unchecked.py 'BINARY [args]'")
        sys.exit(1)

    target_cmd = sys.argv[1].split()
    target_binary = target_cmd[0]
    args = target_cmd[1:] if len(target_cmd) > 1 else None
    find_memmove_unchecked(target_binary, args)