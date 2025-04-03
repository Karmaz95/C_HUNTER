#!/usr/bin/env python3
"""
Angr script to detect potential out-of-bounds array index writes.

The vulnerability occurs when an array index is used to write data beyond the bounds of the array.
This script tracks memory writes and flags any writes that occur beyond a specified buffer size.

Usage:
    python3 angr_out-of-bounds-array-index-literal.py "BINARY_NAME -arg1 value1 -arg2 value2"

The script is modular and can be imported into a larger program.
"""

import angr
import claripy
import sys

def find_oob_write(target_binary, args=None):
    project = angr.Project(target_binary, auto_load_libs=False)
    state = project.factory.entry_state(args=args)

    # Suppose we know or guess the address and size of 'buf'.
    # You'd typically parse symbols/debug info to do this properly.
    BUF_START = 0x100000  # hypothetical address
    BUF_SIZE = 64         # hypothetical size in bytes

    # We'll track any store that writes beyond BUF_START + BUF_SIZE.
    def track_oob_write(state):
        if state.inspect.address_concretization_action == 'store':
            addr = state.inspect.address_concretization_expr
            if addr.symbolic:
                return  # Could be many addresses, we'd add more checks
            addr_val = state.solver.eval(addr)
            if addr_val >= BUF_START + BUF_SIZE:
                print("Detected potential OOB write at address:", hex(addr_val))
                state.globals['oob_detected'] = True

    # Install angr "hooks" to watch memory writes
    state.inspect.b('address_concretization', when=angr.BP_BEFORE, action=track_oob_write)

    simgr = project.factory.simgr(state)
    simgr.run()

    if any(s.globals.get('oob_detected') for s in simgr.deadended + simgr.errored):
        print("OOB write found.")
    else:
        print("No OOB writes detected.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 angr_oob_write.py 'BINARY [args]'")
        sys.exit(1)
    cmd = sys.argv[1].split()
    bin_name = cmd[0]
    bin_args = cmd[1:] if len(cmd) > 1 else None
    find_oob_write(bin_name, bin_args)