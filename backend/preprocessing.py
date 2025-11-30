"""
Preprocessing module: Cleans and normalizes generated code for analysis.
"""

import re

def clean_code(code: str) -> str:
    # Remove comments, debug prints, and normalize indentation
    code = re.sub(r'#.*', '', code)  # Remove comments
    code = re.sub(r'print\(.*?\)', '', code)  # Remove debug prints
    code = re.sub(r'[^\x00-\x7F]+', '', code)  # Remove non-ASCII
    lines = [ln.rstrip() for ln in code.splitlines() if ln.strip()]
    return '\n'.join(lines)
