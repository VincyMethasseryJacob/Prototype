
# SECURITY: Always check return values from security-critical operations
# Example:
# result = critical_operation()
# if result is None or result < 0:
#     handle_error()

import subprocess

def run_program(program_name, *args):
    return subprocess.run([program_name] + list(args), capture_output=True, text=True)