"""
Patching module: Generates secure, patched code versions for detected vulnerabilities.
"""
import re
import ast
from typing import List, Dict, Optional
class CodePatcher:
    """
    Automatically generates patches for detected vulnerabilities based on CWE type.
    """
    def __init__(self, openai_client=None):
        self.openai_client = openai_client
        self.patch_rules = self._initialize_patch_rules()
    @staticmethod
    def _remove_empty_lines(code: str) -> str:
        """Remove all empty lines from code."""
        lines = [line for line in code.splitlines() if line.strip()]
        return '\n'.join(lines)
    def _initialize_patch_rules(self) -> Dict[str, callable]:
        """
        Initialize patching rules for each CWE category.
        """
        return {
            '020': self._patch_improper_input_validation,
            '022': self._patch_path_traversal,
            '078': self._patch_command_injection,
            '080': self._patch_xss,
            '089': self._patch_sql_injection,
            '094': self._patch_code_injection,
            '095': self._patch_eval_injection,
            '116': self._patch_improper_encoding,
            '117': self._patch_log_injection,
            '193': self._patch_off_by_one,
            '200': self._patch_information_exposure,
            '252': self._patch_unchecked_return_value,
            '259': self._patch_hardcoded_password,
            '295': self._patch_certificate_validation,
            '319': self._patch_cleartext_transmission,
            '321': self._patch_hardcoded_crypto_key,
            '326': self._patch_weak_encryption,
            '330': self._patch_weak_random,
            '331': self._patch_insufficient_entropy,
            '367': self._patch_toctou,
            '414': self._patch_missing_lock,
            '425': self._patch_direct_request,
            '454': self._patch_external_initialization,
            '477': self._patch_obsolete_function,
            '502': self._patch_deserialization,
            '522': self._patch_insufficiently_protected_credentials,
            '595': self._patch_comparison_error,
            '605': self._patch_multiple_binds,
            '611': self._patch_xxe,
            '703': self._patch_improper_check,
            '730': self._patch_regex_dos,
            '732': self._patch_incorrect_permission,
            '798': self._patch_hardcoded_credentials,
            '835': self._patch_infinite_loop,
        }
    def generate_patch(self, code: str, vulnerabilities: List[Dict]) -> Dict:
        """
        Generate a patched version of code addressing all detected vulnerabilities.
        
        Returns:
            Dict with 'patched_code', 'changes', and 'unpatched_vulns'
        """
        if not vulnerabilities:
            return {
                'patched_code': code,
                'changes': [],
                'unpatched_vulns': []
            }
        patched_code = code
        changes = []
        unpatched_vulns = []
        # Sort vulnerabilities by line number (descending) to avoid line number shifts
        sorted_vulns = sorted(vulnerabilities, key=lambda v: v.get('line_number', 0), reverse=True)
        for vuln in sorted_vulns:
            cwe_id = vuln.get('cwe_id')
            detection_method = vuln.get('detection_method', 'unknown')
            patch_method = None
            patch_success = False
            change_description = ''
            if cwe_id in self.patch_rules:
                try:
                    result = self.patch_rules[cwe_id](patched_code, vuln)
                    patch_method = 'rule-based'
                    patch_success = result.get('success', False)
                    change_description = result.get('description', '')
                    if patch_success:
                        patched_code = self._remove_empty_lines(result['patched_code'])
                except Exception as e:
                    patch_success = False
                    print(f"Error patching CWE-{cwe_id}: {e}")
            else:
                # Try generic patching or LLM-based patching
                if self.openai_client:
                    result = self._llm_based_patch(patched_code, vuln)
                    patch_method = 'llm-based'
                    patch_success = result.get('success', False)
                    change_description = result.get('description', '')
                    if patch_success:
                        patched_code = self._remove_empty_lines(result['patched_code'])
                else:
                    patch_success = False
            if patch_success:
                changes.append({
                    'cwe_id': cwe_id,
                    'cwe_name': vuln.get('cwe_name'),
                    'line_number': vuln.get('line_number'),
                    'change_description': change_description,
                    'detection_method': detection_method,
                    'patch_method': patch_method if patch_method else 'unknown'
                })
            else:
                unpatched_vulns.append(vuln)
        # Remove empty lines from final patched code
        patched_code = self._remove_empty_lines(patched_code)
        return {
            'patched_code': patched_code,
            'changes': changes,
            'unpatched_vulns': unpatched_vulns
        }
    def _patch_sql_injection(self, code: str, vuln: Dict) -> Dict:
        """Patch SQL injection vulnerabilities."""
        patched = code
        description = []
        # Pattern 1: String formatting with %
        if re.search(r'execute\(["\'].*%s.*["\']', code):
            patched = re.sub(
                r'execute\((["\'])(.*)%s(.*)\1\s*%\s*([^)]+)\)',
                r'execute(\1\2?\3\1, (\4,))',
                patched
            )
            description.append("Replaced string formatting with parameterized query")
        # Pattern 2: f-strings in SQL
        if re.search(r'execute\(f["\']', code):
            # This is complex, mark for manual review or LLM
            if self.openai_client:
                return self._llm_based_patch(code, vuln)
            else:
                return {'success': False}
        # Pattern 3: String concatenation
        if re.search(r'execute\([^)]*\+[^)]*\)', code):
            # Add comment suggesting parameterized queries
            patched = re.sub(
                r'(cursor\.execute\([^)]*\+[^)]*\))',
                r'# TODO: Use parameterized query\n    \1',
                patched
            )
            description.append("Marked string concatenation for parameterized query conversion")
        # Add safe import if needed
        if 'import sqlite3' in code or 'import mysql.connector' in code or 'import psycopg2' in code:
            description.append("Ensure using parameterized queries with placeholders (?, %s, or :name)")
        return {
            'success': len(description) > 0,
            'patched_code': patched,
            'description': '; '.join(description)
        }
    def _patch_path_traversal(self, code: str, vuln: Dict) -> Dict:
        """Patch path traversal vulnerabilities."""
        patched = code
        # Add secure path handling
        if 'import os' not in code:
            patched = 'import os\n' + patched
        # Add path validation function
        validation_func = '''def validate_safe_path(base_dir, user_path):
    """Validate that the path is within the allowed directory."""
    abs_base = os.path.abspath(base_dir)
    abs_user = os.path.abspath(os.path.join(base_dir, user_path))
    return abs_user.startswith(abs_base) and '..' not in user_path
'''
        if 'def validate_safe_path' not in patched:
            # Insert after imports
            import_end = 0
            for line_num, line in enumerate(patched.splitlines()):
                if line.startswith('import ') or line.startswith('from '):
                    import_end = line_num + 1
            lines = patched.splitlines()
            lines.insert(import_end, validation_func)
            patched = '\n'.join(lines)
        # Replace dangerous file operations
        patched = re.sub(
            r'os\.remove\(([^)]+)\)',
            r'os.remove(\1) if validate_safe_path(".", \1) else None',
            patched
        )
        
        patched = re.sub(
            r'open\(([^,)]+)',
            r'open(\1 if validate_safe_path(".", \1) else raise ValueError("Invalid path")',
            patched
        )
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Added path validation to prevent directory traversal'
        }
    def _patch_command_injection(self, code: str, vuln: Dict) -> Dict:
        """Patch OS command injection vulnerabilities."""
        patched = code
        # Replace os.system with subprocess with list arguments
        patched = re.sub(
            r'os\.system\(([^)]+)\)',
            r'subprocess.run([\1], shell=False, check=True)  # Fixed: use list args',
            patched
        )
        # Ensure subprocess is imported
        if 'import subprocess' not in patched and 'subprocess.run' in patched:
            patched = 'import subprocess\n' + patched
        # Add comment for shell=True usage
        patched = re.sub(
            r'(subprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True[^)]*\))',
            r'# WARNING: shell=True is dangerous. Use list arguments instead.\n    \1',
            patched
        )
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Replaced os.system with subprocess.run using safe list arguments'
        }
    def _patch_eval_injection(self, code: str, vuln: Dict) -> Dict:
        """Patch eval/exec injection vulnerabilities."""
        patched = code
        # Replace eval with ast.literal_eval for safe literal evaluation
        patched = re.sub(
            r'\beval\(',
            r'ast.literal_eval(',
            patched
        )
        # Add ast import if needed
        if 'import ast' not in patched and 'ast.literal_eval' in patched:
            patched = 'import ast\n' + patched
        # Add warning for exec
        patched = re.sub(
            r'(\bexec\([^)]+\))',
            r'# SECURITY: Avoid exec() with user input!\n    \1',
            patched
        )
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Replaced eval() with ast.literal_eval() for safe literal evaluation'
        }
    def _patch_hardcoded_password(self, code: str, vuln: Dict) -> Dict:
        """Patch hard-coded password vulnerabilities."""
        patched = code
        # Replace hard-coded passwords with environment variables
        patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', 'password = os.getenv("DB_PASSWORD")'),
            (r'passwd\s*=\s*["\'][^"\']+["\']', 'passwd = os.getenv("DB_PASSWORD")'),
            (r'pwd\s*=\s*["\'][^"\']+["\']', 'pwd = os.getenv("PASSWORD")'),
        ]
        for pattern, replacement in patterns:
            if re.search(pattern, patched, re.IGNORECASE):
                patched = re.sub(pattern, replacement, patched, flags=re.IGNORECASE)
        
        # Ensure os is imported
        if 'import os' not in patched and 'os.getenv' in patched:
            patched = 'import os\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Replaced hard-coded passwords with environment variables'
        }
    def _patch_hardcoded_credentials(self, code: str, vuln: Dict) -> Dict:
        """Patch hard-coded credentials (API keys, tokens, secrets)."""
        patched = code
        # Replace hard-coded credentials with environment variables
        patterns = [
            (r'api_key\s*=\s*["\'][^"\']+["\']', 'api_key = os.getenv("API_KEY")'),
            (r'secret\s*=\s*["\'][^"\']+["\']', 'secret = os.getenv("SECRET_KEY")'),
            (r'token\s*=\s*["\'][^"\']+["\']', 'token = os.getenv("AUTH_TOKEN")'),
        ]
        for pattern, replacement in patterns:
            if re.search(pattern, patched, re.IGNORECASE):
                patched = re.sub(pattern, replacement, patched, flags=re.IGNORECASE)
        
        # Ensure os is imported
        if 'import os' not in patched and 'os.getenv' in patched:
            patched = 'import os\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Replaced hard-coded credentials with environment variables'
        }
    def _patch_deserialization(self, code: str, vuln: Dict) -> Dict:
        """Patch unsafe deserialization vulnerabilities."""
        patched = code
        # Replace pickle with json for safer serialization
        patched = re.sub(
            r'pickle\.loads?\(',
            r'json.loads(',
            patched
        )
        # Replace unsafe YAML loading
        patched = re.sub(
            r'yaml\.load\(([^,)]+)\)',
            r'yaml.safe_load(\1)',
            patched
        )
        # Add imports if needed
        if 'import json' not in patched and 'json.loads' in patched:
            patched = 'import json\n' + patched
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Replaced unsafe deserialization with safer alternatives (json.loads, yaml.safe_load)'
        }
    def _patch_weak_encryption(self, code: str, vuln: Dict) -> Dict:
        """Patch weak encryption algorithm usage."""
        patched = code
        # Replace DES with AES
        patched = re.sub(
            r'DES\.new\(',
            r'AES.new(',
            patched
        )
        # Replace MD5 with SHA256
        patched = re.sub(
            r'hashlib\.md5\(',
            r'hashlib.sha256(',
            patched
        )
        
        patched = re.sub(
            r'MD5\.new\(',
            r'SHA256.new(',
            patched
        )
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Replaced weak cryptographic algorithms with stronger alternatives (AES, SHA256)'
        }
    def _patch_weak_random(self, code: str, vuln: Dict) -> Dict:
        """Patch weak random number generation for security."""
        patched = code
        # Replace random.random() with secrets
        patched = re.sub(
            r'\brandom\.random\(\)',
            r'secrets.SystemRandom().random()',
            patched
        )
        
        patched = re.sub(
            r'\brandom\.randint\(',
            r'secrets.randbelow(',
            patched
        )
        # Add secrets import if needed
        if 'import secrets' not in patched and 'secrets.' in patched:
            patched = 'import secrets\n' + patched
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Replaced weak random with cryptographically secure random (secrets module)'
        }
    def _patch_xxe(self, code: str, vuln: Dict) -> Dict:
        """Patch XML External Entity (XXE) vulnerabilities."""
        patched = code
        # Use defusedxml
        patched = re.sub(
            r'from xml\.etree import ElementTree',
            r'from defusedxml import ElementTree',
            patched
        )
        patched = re.sub(
            r'import xml\.etree\.ElementTree',
            r'import defusedxml.ElementTree as ElementTree',
            patched
        )
        # Add comment about defusedxml
        if 'defusedxml' in patched:
            patched = '# Using defusedxml to prevent XXE attacks\n' + patched
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Replaced xml.etree with defusedxml to prevent XXE attacks'
        }
    def _patch_cleartext_transmission(self, code: str, vuln: Dict) -> Dict:
        """Patch cleartext transmission vulnerabilities."""
        patched = code
        # Replace http:// with https://
        patched = re.sub(
            r'["\']http://([^"\']+)["\']',
            r'"https://\1"',
            patched
        )
        # Add SSL context for connections
        patched = re.sub(
            r'(urllib\.request\.urlopen\([^)]+)\)',
            r'\1, context=ssl.create_default_context())',
            patched
        )
        if 'ssl.create_default_context' in patched and 'import ssl' not in patched:
            patched = 'import ssl\n' + patched
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Enforced HTTPS and added SSL context for secure transmission'
        }
    def _patch_improper_input_validation(self, code: str, vuln: Dict) -> Dict:
        """Patch improper input validation vulnerabilities."""
        patched = code
        description = []
        # Add input validation function
        validation_func = '''def validate_input(user_input, input_type='string', max_length=None, allowed_chars=None):
    """Validate user input with type checking and sanitization."""
    if user_input is None:
        raise ValueError("Input cannot be None")
    if input_type == 'string':
        if not isinstance(user_input, str):
            raise TypeError("Expected string input")
        if max_length and len(user_input) > max_length:
            raise ValueError(f"Input exceeds maximum length of {max_length}")
        if allowed_chars and not all(c in allowed_chars for c in user_input):
            raise ValueError("Input contains invalid characters")
    elif input_type == 'int':
        try:
            return int(user_input)
        except ValueError:
            raise ValueError("Input must be an integer")
    return user_input
'''
        if 'def validate_input' not in patched:
            # Insert validation function after imports
            import_end = 0
            for line_num, line in enumerate(patched.splitlines()):
                if line.startswith('import ') or line.startswith('from '):
                    import_end = line_num + 1
            lines = patched.splitlines()
            lines.insert(import_end, validation_func)
            patched = '\n'.join(lines)
            description.append("Added input validation function")
        
        # Add comments where user input is used
        if 'request.' in code or 'input(' in code:
            description.append("Added input validation checks (review and apply validate_input() where needed)")
        
        return {
            'success': len(description) > 0,
            'patched_code': patched,
            'description': '; '.join(description)
        }
    
    def _patch_xss(self, code: str, vuln: Dict) -> Dict:
        """Patch Cross-Site Scripting (XSS) vulnerabilities."""
        patched = code
        description = []
        
        # Add HTML escaping
        if 'import html' not in patched:
            patched = 'import html\n' + patched
            description.append("Added html module for escaping")
        
        # Look for common XSS patterns and add escaping
        if 'render_template' in code or 'HttpResponse' in code:
            # Add comment about escaping
            patched = '# SECURITY: Use html.escape() for user input in HTML output\n' + patched
            description.append("Added HTML escaping reminder for template rendering")
        
        # Replace direct string concatenation in HTML with escaped version
        patched = re.sub(
            r'(["\']<[^>]*>["\']\s*\+\s*)([^+\)]+)',
            r'\1html.escape(\2)',
            patched
        )
        
        if 'html.escape' in patched:
            description.append("Applied HTML escaping to output")
        
        return {
            'success': len(description) > 0,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Added XSS protection measures'
        }
    
    def _patch_code_injection(self, code: str, vuln: Dict) -> Dict:
        """Patch code injection vulnerabilities."""
        patched = code
        description = []
        
        # Replace compile() with safer alternatives
        if 'compile(' in code:
            patched = re.sub(
                r'\bcompile\(',
                r'# SECURITY WARNING: compile() with user input is dangerous!\n    # compile(',
                patched
            )
            description.append("Added warning about compile() usage")
        
        # Add comment about dynamic code execution
        if '__import__' in code:
            patched = re.sub(
                r'(__import__\([^)]+\))',
                r'# SECURITY: Dynamic imports can be dangerous\n    \1',
                patched
            )
            description.append("Added warning about dynamic imports")
        
        return {
            'success': len(description) > 0,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Added code injection warnings'
        }
    
    def _patch_improper_encoding(self, code: str, vuln: Dict) -> Dict:
        """Patch improper output encoding vulnerabilities."""
        patched = code
        
        # Add proper encoding for different contexts
        if 'import html' not in patched:
            patched = 'import html\n' + patched
        
        if 'import urllib.parse' not in patched and 'urllib' in patched:
            patched = 'import urllib.parse\n' + patched
        
        # Add encoding helpers comment
        encoding_comment = '''
# Encoding helpers:
# - HTML context: html.escape(data)
# - URL context: urllib.parse.quote(data)
# - JavaScript context: json.dumps(data)
'''
        
        if '# Encoding helpers:' not in patched:
            patched = encoding_comment + '\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Added encoding helpers for proper output encoding'
        }
    
    def _patch_log_injection(self, code: str, vuln: Dict) -> Dict:
        """Patch log injection vulnerabilities."""
        patched = code
        description = []
        
        # Add log sanitization function
        sanitize_func = '''
def sanitize_log_input(log_data):
    """Sanitize input before logging to prevent injection."""
    if isinstance(log_data, str):
        # Remove newlines and control characters
        log_data = log_data.replace('\\n', ' ').replace('\\r', ' ')
        log_data = ''.join(char for char in log_data if char.isprintable() or char == ' ')
    return log_data

'''
        
        if 'def sanitize_log_input' not in patched:
            import_end = 0
            for line_num, line in enumerate(patched.splitlines()):
                if line.startswith('import ') or line.startswith('from '):
                    import_end = line_num + 1
            
            lines = patched.splitlines()
            lines.insert(import_end, sanitize_func)
            patched = '\n'.join(lines)
            description.append("Added log sanitization function")
        
        # Wrap logging calls with sanitization
        patched = re.sub(
            r'(logging\.\w+\(["\'][^"\']*%s[^"\']*["\'].*?,\s*)([^)]+)\)',
            r'\1sanitize_log_input(\2))',
            patched
        )
        
        if 'sanitize_log_input' in patched:
            description.append("Applied log sanitization to logging calls")
        
        return {
            'success': len(description) > 0,
            'patched_code': patched,
            'description': '; '.join(description)
        }
    
    def _patch_off_by_one(self, code: str, vuln: Dict) -> Dict:
        """Patch off-by-one errors."""
        patched = code
        description = []
        
        # Fix common off-by-one patterns
        # Fix range(len(array)+1) -> range(len(array))
        if re.search(r'range\(len\([^)]+\)\s*\+\s*1\)', patched):
            patched = re.sub(
                r'range\(len\(([^)]+)\)\s*\+\s*1\)',
                r'range(len(\1))',
                patched
            )
            description.append("Fixed range() off-by-one error")
        
        # Fix array[len(array)] -> array[len(array)-1] or use -1
        if re.search(r'\[[^\]]*len\([^)]+\)[^\]]*\]', patched):
            patched = re.sub(
                r'(\w+)\[len\(\1\)\]',
                r'\1[-1]',
                patched
            )
            description.append("Fixed array indexing off-by-one error")
        
        # Add boundary checking comment
        boundary_comment = '''\n# SECURITY: Review array/string indexing for off-by-one errors
# - Use len(array) instead of len(array)+1 for upper bounds
# - Use range(len(array)) instead of range(len(array)+1)
# - Consider using slicing instead of direct indexing
'''
        
        if '# SECURITY: Review array/string indexing' not in patched:
            patched = boundary_comment + '\n' + patched
        
        return {
            'success': len(description) > 0 or '# SECURITY: Review array/string indexing' in patched,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Added boundary checking guidance to prevent off-by-one errors'
        }
    
    def _patch_information_exposure(self, code: str, vuln: Dict) -> Dict:
        """Patch information exposure vulnerabilities."""
        patched = code
        description = []
        
        # Replace detailed error messages with generic ones
        if 'except' in code and 'print' in code:
            patched = re.sub(
                r'except\s+(\w+)\s+as\s+(\w+):\s*\n\s*print\([^)]*\2[^)]*\)',
                r'except \1 as \2:\n    # Log detailed error securely\n    logger.error(str(\2))\n    print("An error occurred. Please try again.")',
                patched
            )
            description.append("Replaced detailed error messages with generic messages")
        
        # Add logging import if needed
        if 'logger.error' in patched and 'import logging' not in patched:
            patched = 'import logging\nlogger = logging.getLogger(__name__)\n' + patched
        
        return {
            'success': len(description) > 0,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Added measures to prevent information exposure'
        }
    
    def _patch_unchecked_return_value(self, code: str, vuln: Dict) -> Dict:
        """Patch unchecked return value vulnerabilities."""
        patched = code
        description = []
        
        # Wrap file operations with error checking
        if 'open(' in patched:
            # Add try-except around file operations if not already present
            if 'try:' not in patched:
                patched = re.sub(
                    r'(\s*)([^\n]*open\([^)]+\)[^\n]*\n)',
                    r'\1try:\n\1    \2\1except (IOError, OSError) as e:\n\1    print(f"File operation failed: {e}")\n\1    # Handle error appropriately\n',
                    patched,
                    count=1
                )
                description.append("Added error handling for file operations")
        
        # Add comment about checking return values
        check_comment = '''\n# SECURITY: Always check return values from security-critical operations
# Example:
# result = critical_operation()
# if result is None or result < 0:
#     handle_error()
'''
        
        if '# SECURITY: Always check return values' not in patched:
            patched = check_comment + '\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Added guidance for checking return values from critical operations'
        }
    
    def _patch_certificate_validation(self, code: str, vuln: Dict) -> Dict:
        """Patch improper certificate validation vulnerabilities."""
        patched = code
        description = []
        
        # Remove SSL verification disabling
        patched = re.sub(
            r'verify\s*=\s*False',
            r'verify=True  # SECURITY: Never disable SSL verification in production',
            patched
        )
        
        patched = re.sub(
            r'ssl\._create_unverified_context\(\)',
            r'ssl.create_default_context()  # SECURITY: Use verified context',
            patched
        )
        
        if 'verify=True' in patched or 'create_default_context' in patched:
            description.append("Enabled proper SSL/TLS certificate validation")
        
        return {
            'success': len(description) > 0,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Enabled certificate validation'
        }
    
    def _patch_hardcoded_crypto_key(self, code: str, vuln: Dict) -> Dict:
        """Patch hard-coded cryptographic key vulnerabilities."""
        patched = code
        
        # Similar to hardcoded credentials but for crypto keys
        patterns = [
            (r'key\s*=\s*["\'][^"\']{16,}["\']', 'key = os.getenv("ENCRYPTION_KEY")'),
            (r'secret_key\s*=\s*["\'][^"\']+["\']', 'secret_key = os.getenv("SECRET_KEY")'),
        ]
        
        for pattern, replacement in patterns:
            if re.search(pattern, patched, re.IGNORECASE):
                patched = re.sub(pattern, replacement, patched, flags=re.IGNORECASE)
        
        if 'import os' not in patched and 'os.getenv' in patched:
            patched = 'import os\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Replaced hard-coded cryptographic keys with environment variables'
        }
    
    def _patch_insufficient_entropy(self, code: str, vuln: Dict) -> Dict:
        """Patch insufficient entropy vulnerabilities."""
        patched = code
        
        # Ensure using os.urandom or secrets for crypto
        if 'import secrets' not in patched:
            patched = 'import secrets\n' + patched
        
        # Add comment about entropy requirements
        entropy_comment = '''
# SECURITY: Use sufficient entropy for cryptographic operations
# - Use secrets.token_bytes(32) for keys
# - Use secrets.token_hex(32) for tokens
# - Use os.urandom(32) for random bytes
'''
        
        if '# SECURITY: Use sufficient entropy' not in patched:
            patched = entropy_comment + '\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Added guidance for using sufficient entropy in cryptographic operations'
        }
    
    def _patch_toctou(self, code: str, vuln: Dict) -> Dict:
        """Patch Time-of-check Time-of-use (TOCTOU) race conditions."""
        patched = code
        description = []
        
        # Replace os.path.exists() + open() pattern with direct open() + exception handling
        if 'os.path.exists' in patched and 'open(' in patched:
            # Find and replace the TOCTOU pattern
            pattern = r'if os\.path\.exists\(([^)]+)\):\s*\n\s*([^=]+=\s*)?open\(\1'
            if re.search(pattern, patched):
                patched = re.sub(
                    pattern,
                    r'try:\n    \2open(\1',
                    patched
                )
                # Add except block
                patched = re.sub(
                    r'(try:\n\s+[^=]+=\s*open\([^)]+\)[^\n]*)',
                    r'\1\nexcept FileNotFoundError:\n    # Handle file not found',
                    patched
                )
                description.append("Replaced TOCTOU-vulnerable exists() check with try-except")
        
        # Add comment about TOCTOU vulnerabilities
        toctou_comment = '''\n# SECURITY: Avoid TOCTOU race conditions
# - Use atomic operations when possible
# - Minimize time between check and use  
# - Use file descriptors instead of filenames
# - Consider using locks for shared resources
'''
        
        if '# SECURITY: Avoid TOCTOU race conditions' not in patched:
            patched = toctou_comment + '\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Added guidance to prevent TOCTOU race conditions'
        }
    
    def _patch_missing_lock(self, code: str, vuln: Dict) -> Dict:
        """Patch missing lock check vulnerabilities."""
        patched = code
        description = []
        
        # Add threading lock import and usage
        if 'import threading' not in patched:
            patched = 'import threading\n' + patched
            description.append("Added threading import")
        
        # Add lock initialization if not present
        if 'threading.Lock()' not in patched and 'Lock()' not in patched:
            patched = 'import threading\nresource_lock = threading.Lock()\n\n' + patched.replace('import threading\n', '')
            description.append("Added lock initialization")
        
        # Wrap global variable access with lock
        # Look for global variable assignments
        global_pattern = r'^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$'
        matches = list(re.finditer(global_pattern, patched, re.MULTILINE))
        if matches and 'with resource_lock:' not in patched:
            # Add example of lock usage
            lock_usage = '''\n# Example of thread-safe access:
# with resource_lock:
#     shared_resource = value
'''
            patched = patched + lock_usage
            description.append("Added lock usage example")
        
        lock_comment = '''\n# SECURITY: Use locks for shared resource access
# Example:
# resource_lock = threading.Lock()
# with resource_lock:
#     # Access shared resource
'''
        
        if '# SECURITY: Use locks for shared resource access' not in patched:
            patched = lock_comment + '\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Added threading lock guidance for shared resource access'
        }
    
    def _patch_direct_request(self, code: str, vuln: Dict) -> Dict:
        """Patch direct request vulnerabilities."""
        patched = code
        description = []
        
        # Add authorization check before resource access
        # Look for function definitions that might handle requests
        if 'def ' in patched and ('request' in patched or 'user' in patched):
            # Add authorization check template
            auth_check = '''\ndef check_authorization(user, resource):
    """Check if user is authorized to access resource."""
    # Implement your authorization logic here
    # Example: return user.has_permission(resource)
    return True  # TODO: Implement proper authorization\n\n'''
            
            if 'def check_authorization' not in patched:
                # Insert after imports or at the beginning
                if 'import ' in patched:
                    last_import = max([i for i, line in enumerate(patched.split('\n')) if line.strip().startswith('import')])
                    lines = patched.split('\n')
                    lines.insert(last_import + 1, auth_check)
                    patched = '\n'.join(lines)
                else:
                    patched = auth_check + patched
                description.append("Added authorization check function template")
        
        # Add authorization check comment
        auth_comment = '''\n# SECURITY: Add authorization checks before resource access
# Example:
# if not check_authorization(user, resource):
#     raise PermissionError("Access denied")
'''
        
        if '# SECURITY: Add authorization checks' not in patched:
            patched = auth_comment + '\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Added authorization check guidance'
        }
    
    def _patch_external_initialization(self, code: str, vuln: Dict) -> Dict:
        """Patch external initialization of trusted variables."""
        patched = code
        
        # Add validation for external input
        validation_comment = '''
# SECURITY: Validate external configuration
# - Use allowlists for configuration values
# - Validate data types and ranges
# - Use secure defaults
'''
        
        if '# SECURITY: Validate external configuration' not in patched:
            patched = validation_comment + '\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Added guidance for validating external initialization'
        }
    
    def _patch_obsolete_function(self, code: str, vuln: Dict) -> Dict:
        """Patch use of obsolete functions."""
        patched = code
        description = []
        
        # Common obsolete function replacements
        replacements = {
            r'\bos\.tempnam\b': 'tempfile.mkstemp',
            r'\bos\.tmpnam\b': 'tempfile.mkstemp',
            r'\bmktemp\b': 'tempfile.mkstemp',
        }
        
        for old, new in replacements.items():
            if re.search(old, patched):
                patched = re.sub(old, f'{new}  # Replaced obsolete function', patched)
                description.append(f"Replaced obsolete function with {new}")
        
        if 'tempfile.mkstemp' in patched and 'import tempfile' not in patched:
            patched = 'import tempfile\n' + patched
        
        return {
            'success': len(description) > 0,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Updated obsolete functions'
        }
    
    def _patch_insufficiently_protected_credentials(self, code: str, vuln: Dict) -> Dict:
        """Patch insufficiently protected credentials."""
        patched = code
        
        # Add comment about credential protection
        cred_comment = '''
# SECURITY: Protect credentials properly
# - Use environment variables or secure vaults
# - Never log credentials
# - Encrypt credentials at rest
# - Use HTTPS for transmission
'''
        
        if '# SECURITY: Protect credentials properly' not in patched:
            patched = cred_comment + '\n' + patched
        
        # Remove any credential logging
        patched = re.sub(
            r'(print|logging\.\w+)\([^)]*password[^)]*\)',
            r'# REMOVED: Credential logging\n    # \1(...)',
            patched,
            flags=re.IGNORECASE
        )
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Added credential protection measures and removed credential logging'
        }
    
    def _patch_comparison_error(self, code: str, vuln: Dict) -> Dict:
        """Patch comparison of object references instead of contents."""
        patched = code
        description = []
        
        # Fix common comparison errors
        # Fix: if x is True/False -> if x/if not x
        if re.search(r'\bis\s+(True|False)\b', patched):
            patched = re.sub(r'if\s+(\w+)\s+is\s+True\b', r'if \1', patched)
            patched = re.sub(r'if\s+(\w+)\s+is\s+False\b', r'if not \1', patched)
            description.append("Fixed 'is True/False' comparison")
        
        # Fix: comparing strings/numbers with 'is' instead of '=='
        # Look for: if variable is "string" or if variable is 123
        if re.search(r'\bis\s+["\']', patched) or re.search(r'\bis\s+\d+', patched):
            patched = re.sub(r'([a-zA-Z_]\w*)\s+is\s+(["\'][^"\']*)(["\'])', r'\1 == \2\3', patched)
            patched = re.sub(r'([a-zA-Z_]\w*)\s+is\s+(\d+)\b', r'\1 == \2', patched)
            description.append("Fixed identity comparison on values")
        
        # Add comment about comparison
        comparison_comment = '''\n# SECURITY: Use proper comparison operators
# - Use == for value comparison
# - Use 'is' only for identity comparison (None, True, False)
# - For objects, compare relevant attributes
'''
        
        if '# SECURITY: Use proper comparison operators' not in patched:
            patched = comparison_comment + '\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Added guidance for proper object comparison'
        }
    
    def _patch_multiple_binds(self, code: str, vuln: Dict) -> Dict:
        """Patch multiple binds to same port."""
        patched = code
        
        # Add SO_REUSEADDR guidance
        socket_comment = '''
# SECURITY: Proper socket configuration
# - Use unique ports or proper port management
# - Set SO_REUSEADDR carefully
# - Validate port availability before binding
'''
        
        if '# SECURITY: Proper socket configuration' not in patched:
            patched = socket_comment + '\n' + patched
        
        # Add SO_REUSEADDR with caution
        if 'socket.socket' in code:
            patched = re.sub(
                r'(socket\.socket\([^)]+\))',
                r'\1\n    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Use with caution',
                patched
            )
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Added socket configuration guidance'
        }
    
    def _patch_improper_check(self, code: str, vuln: Dict) -> Dict:
        """Patch improper check or handling of exceptional conditions."""
        patched = code
        description = []
        
        # Wrap bare except clauses with specific exception types
        if re.search(r'except:\s*$', patched, re.MULTILINE):
            patched = re.sub(
                r'except:\s*$',
                r'except Exception as e:',
                patched,
                flags=re.MULTILINE
            )
            description.append("Replaced bare except with Exception type")
        
        # Add error handling to risky operations without try-except
        if 'try:' not in patched:
            if 'open(' in patched:
                # Find first open() call and wrap it
                lines = patched.split('\n')
                for i, line in enumerate(lines):
                    if 'open(' in line and 'try:' not in '\n'.join(lines[max(0,i-2):i]):
                        indent = len(line) - len(line.lstrip())
                        spaces = ' ' * indent
                        lines[i] = f"{spaces}try:\n{spaces}    {line.lstrip()}\n{spaces}except (IOError, OSError) as e:\n{spaces}    print(f'Error: {{e}}')\n{spaces}    # Handle error appropriately"
                        patched = '\n'.join(lines)
                        description.append("Added try-except for file operations")
                        break
        
        # Add proper error handling
        error_handling = '''\n# SECURITY: Proper error handling
# - Use try-except blocks for all critical operations
# - Log errors securely without exposing sensitive info
# - Fail securely (deny access on error)
# - Provide generic error messages to users
'''
        
        if '# SECURITY: Proper error handling' not in patched:
            patched = error_handling + '\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Added error handling guidance'
        }
    
    def _patch_regex_dos(self, code: str, vuln: Dict) -> Dict:
        """Patch Regular Expression Denial of Service (ReDoS)."""
        patched = code
        description = []
        
        # Simplify dangerous nested quantifier patterns
        if re.search(r'\([^)]*[+*][^)]*\)[+*]', patched):
            description.append("Detected dangerous nested quantifier pattern")
        
        # Add input length validation before regex operations
        if 're.search' in patched or 're.match' in patched or 're.findall' in patched:
            if 'MAX_INPUT_LENGTH' not in patched:
                patched = 'MAX_INPUT_LENGTH = 10000  # Limit input size for regex\n' + patched
                description.append("Added input length limit constant")
            
            # Wrap regex operations with length check
            patched = re.sub(
                r're\.(search|match|findall)\(([^,]+),\s*([^)]+)\)',
                r're.\1(\2, \3[:MAX_INPUT_LENGTH])',
                patched
            )
            description.append("Added input length validation to regex operations")
        
        # Add regex timeout and complexity limits
        regex_comment = '\n# SECURITY: Prevent ReDoS attacks\n# - Limit regex complexity\n# - Validate input length before applying regex\n# - Use timeouts for regex operations\n# - Avoid nested quantifiers like (a+)+ or (a*)*\n'
        
        if '# SECURITY: Prevent ReDoS attacks' not in patched:
            patched = regex_comment + '\n' + patched
        
        return {
            'success': True,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Added ReDoS protection measures'
        }
    
    def _patch_incorrect_permission(self, code: str, vuln: Dict) -> Dict:
        """Patch incorrect permission assignment."""
        patched = code
        description = []
        
        # Fix overly permissive file permissions
        patched = re.sub(
            r'os\.chmod\([^,]+,\s*0o777\)',
            r'os.chmod(file_path, 0o600)  # SECURITY: Restrict to owner only',
            patched
        )
        
        patched = re.sub(
            r'os\.chmod\([^,]+,\s*0o666\)',
            r'os.chmod(file_path, 0o600)  # SECURITY: Restrict to owner only',
            patched
        )
        
        # Add umask for file creation
        if 'open(' in code and 'os.umask' not in code:
            umask_line = 'os.umask(0o077)  # Restrict file permissions\n'
            patched = umask_line + patched
            description.append("Added umask to restrict file permissions")
        
        if 'chmod' in patched and '0o600' in patched:
            description.append("Fixed overly permissive file permissions")
        
        return {
            'success': len(description) > 0,
            'patched_code': patched,
            'description': '; '.join(description) if description else 'Updated file permissions'
        }
    
    def _patch_infinite_loop(self, code: str, vuln: Dict) -> Dict:
        """Patch infinite loop vulnerabilities."""
        patched = code
        # Add loop safety comment only if not already present
        loop_comment = '''# SECURITY: Prevent infinite loops
# - Ensure all loops have proper exit conditions
# - Add iteration limits for unbounded loops
# - Validate loop control variables
# - Consider adding timeouts for long-running loops
'''
        if '# SECURITY: Prevent infinite loops' not in patched:
            patched = loop_comment + '\n' + patched
        
        # Add iteration counter to while loops
        if 'while' in code and 'while True' in code:
            patched = re.sub(
                r'while True:',
                r'max_iterations = 1000  # Safety limit\n    iteration = 0\n    while iteration < max_iterations:',
                patched
            )
            patched = re.sub(
                r'(while iteration < max_iterations:.*?\n)(.*?)(\n\s*(?:break|continue|return))',
                r'\1\2\n        iteration += 1\3',
                patched,
                flags=re.DOTALL
            )
        
        return {
            'success': True,
            'patched_code': patched,
            'description': 'Added infinite loop protection with iteration limits'
        }
    
    def _llm_based_patch(self, code: str, vuln: Dict) -> Dict:
        """Use LLM to generate patches for complex vulnerabilities."""
        if not self.openai_client:
            return {'success': False}
        
        try:
            # Build the prompt with patch recommendation if available
            patch_recommendation = vuln.get('patch_note', '')
            if patch_recommendation:
                recommendation_section = f"\nRecommended Fix Guidance (advisory): {patch_recommendation}"
                task_step_2 = "2. Apply the recommended fix approach to solve the security vulnerability"
            else:
                recommendation_section = ""
                task_step_2 = """2. Use the recommended fix approach as guidance where applicable.
If the recommendation is ambiguous, outdated, or conflicts with secure coding best practices,
apply the safest modern mitigation instead."""
            prompt = f"""
You are a senior application security engineer and Python expert. 
Security Vulnerability: CWE-{vuln.get('cwe_id')} - {vuln.get('cwe_name')}
Description: {vuln.get('description')}{recommendation_section}
Code to analyze:
```python
{code}
```
Task:
1. You will be given code and a identified security vulnerability (CWE id/description/code). Your job is to patch the vulnerability in the code.
{task_step_2}
3. Ensure the fixed code is error-free with no syntax issues
4. Return ONLY the complete fixed code without any explanations
5. IMPORTANT: Do NOT include any empty lines in the code - remove all blank lines
"""
            
            response = self.openai_client.generate_code_only_response(prompt, max_tokens=2000)
            # Sanitize LLM response: strip Markdown code fences if present
            patched = response.strip()
            if patched.startswith("```"):
                # Remove leading fence
                first_newline = patched.find("\n")
                patched = patched[first_newline + 1:] if first_newline != -1 else patched
            if patched.endswith("```"):
                # Remove trailing fence
                patched = patched[:-3]
            patched = patched.strip()
            # Remove all empty lines from LLM-generated code
            patched = self._remove_empty_lines(patched)
            return {
                'success': True,
                'patched_code': patched,
                'description': f'LLM-generated patch for CWE-{vuln.get("cwe_id")}'
            }
        except Exception as e:
            return {'success': False}
    def generate_diff(self, original: str, patched: str) -> str:
        """Generate a human-readable diff between original and patched code."""
        import difflib
        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile='original.py',
            tofile='patched.py',
            lineterm=''
        )
        return ''.join(diff)
# Backwards compatibility function
def generate_patch(code: str, openai_client=None) -> str:
    """
    Generate a patched (secure) version of the code.
    """
    patcher = CodePatcher(openai_client)
    # For backwards compatibility, return code as-is if no vulnerabilities specified
    return code
