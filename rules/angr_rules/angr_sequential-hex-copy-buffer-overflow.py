#!/usr/bin/env python3
"""
Angr script to detect potential sequential hex copy buffer overflow.

The vulnerability occurs when hex data is sequentially copied from an input buffer
into a fixed-size stack buffer without proper bounds checking. This script uses a heuristic:
it assumes that a local buffer is allocated within a specific range relative to the base pointer
and flags any memory write occurring outside that range.

Usage:
    python3 angr_sequential-hex-copy-buffer-overflow.py "BINARY_NAME -arg1 value1 -arg2 value2"

The script is modular and can be imported into a larger program.
"""

import angr
import sys

def find_sequential_hex_copy_overflow(binary_cmd):
    """
    Analyze the binary for a sequential hex copy buffer overflow vulnerability.
    
    Parameters:
      binary_cmd: A string with the binary name and its arguments.
    """
    target_cmd = binary_cmd.split()
    target_binary = target_cmd[0]
    args = target_cmd[1:] if len(target_cmd) > 1 else []

    project = angr.Project(target_binary, auto_load_libs=False)
    state = project.factory.entry_state(args=[target_binary] + args)
    state.globals['overflow'] = False

    # Heuristic: assume a local buffer is allocated on the stack within 0x200 bytes below BP.
    def get_stack_bounds(state):
        bp = state.regs.bp if hasattr(state.regs, 'bp') else state.regs.rbp
        return (state.solver.eval(bp) - 0x200, state.solver.eval(bp))

    def check_mem_write(state):
        addr = state.inspect.mem_write_address
        if addr is None:
            return
        try:
            concrete_addr = state.solver.eval(addr)
        except Exception:
            return
        safe_start, _ = get_stack_bounds(state)
        if concrete_addr < safe_start:
            state.globals['overflow'] = True

    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=check_mem_write)
    simgr = project.factory.simgr(state)
    simgr.explore(find=lambda s: s.globals.get('overflow', False))
    
    if simgr.found:
        print("Potential sequential hex copy buffer overflow detected.")
        for found_state in simgr.found:
            print("Overflow path found:", found_state)
    else:
        print("No sequential hex copy buffer overflow detected.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: angr_sequential-hex-copy-buffer-overflow.py 'BINARY_NAME -arg1 value1 -arg2 value2'")
        sys.exit(1)
    binary_cmd = sys.argv[1]
    find_sequential_hex_copy_overflow(binary_cmd)