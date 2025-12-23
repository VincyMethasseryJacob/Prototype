"""
Preprocessing module: Cleans and normalizes generated code for analysis.
"""

import re

def clean_code(code: str) -> str:
    """
    Clean and normalize generated code for analysis.
    Removes markdown code fences, comments, debug prints, normalizes formatting, and removes all empty lines.
    """
    # Remove markdown code fences (```python, ```, etc.)
    code = re.sub(r'^```\w*\s*$', '', code, flags=re.MULTILINE)
    code = re.sub(r'^```\s*$', '', code, flags=re.MULTILINE)
    # Process line by line
    lines = code.splitlines()
    cleaned_lines = []
    for line in lines:
        # Remove comments but keep the line (replace with empty line)
        if '#' in line:
            # Keep code before comment, remove comment part
            line = line.split('#')[0]
        # Remove debug prints
        line = re.sub(r'print\(.*?\)', '', line)
        # Remove non-ASCII characters
        line = re.sub(r'[^\x00-\x7F]+', '', line)
        # Strip trailing whitespace
        line = line.rstrip()
        # Only keep non-empty lines
        if line.strip():
            cleaned_lines.append(line)
    return '\n'.join(cleaned_lines)
