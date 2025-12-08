"""
Preprocessing module: Cleans and normalizes generated code for analysis.
"""

import re

def clean_code(code: str) -> str:
    """
    Clean and normalize generated code for analysis.
    Removes markdown code fences, comments, debug prints, and normalizes formatting.
    Preserves line numbers by keeping empty lines where content was removed.
    """
    # Remove markdown code fences (```python, ```, etc.)
    code = re.sub(r'^```\w*\s*$', '', code, flags=re.MULTILINE)
    code = re.sub(r'^```\s*$', '', code, flags=re.MULTILINE)
    
    # Process line by line to preserve line numbers
    lines = code.splitlines()
    cleaned_lines = []
    
    for line in lines:
        # Remove comments but keep the line (replace with empty line to preserve numbering)
        if '#' in line:
            # Keep code before comment, remove comment part
            line = line.split('#')[0]
        
        # Remove debug prints but preserve the line
        line = re.sub(r'print\(.*?\)', '', line)
        
        # Remove non-ASCII characters
        line = re.sub(r'[^\x00-\x7F]+', '', line)
        
        # Strip trailing whitespace but keep the line (even if empty)
        cleaned_lines.append(line.rstrip())
    
    return '\n'.join(cleaned_lines)
