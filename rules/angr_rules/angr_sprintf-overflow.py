# python3 angr_sprintf-overflow.py "./vulnerable_binary -arg1 test -arg2 123"
import angr
import sys
import claripy

def find_sprintf_overflow(target_binary, args=None):
    project = angr.Project(target_binary, auto_load_libs=False)

    # Create an initial state
    state = project.factory.entry_state(args=args)
    
    # Use symbolic execution to find unsafe sprintf calls
    simulation = project.factory.simgr(state)

    def is_sprintf(state):
        """Check if the current state is executing sprintf."""
        return b"sprintf" in state.posix.dumps(1)  # Looking at stdout for evidence

    print(f"Analyzing {target_binary} for sprintf buffer overflows...")
    simulation.explore(find=is_sprintf)

    if simulation.found:
        print("Potential buffer overflow detected in sprintf!")
        for found_state in simulation.found:
            print(f"Exploitability Path: {found_state}")
    else:
        print("No sprintf overflows found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: angr_sprintf-overflow.py 'BINARY_NAME -arg1 value1 -arg2 value2'")
        sys.exit(1)

    # Extract target binary and arguments
    target_cmd = sys.argv[1].split()
    target_binary = target_cmd[0]
    args = target_cmd[1:] if len(target_cmd) > 1 else None

    find_sprintf_overflow(target_binary, args)