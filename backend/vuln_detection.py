"""
Vulnerability Detection module: Dynamically detects vulnerabilities across all CWE categories.
"""

import os
import re
import ast
from typing import List, Dict, Tuple, Set, Optional
from difflib import SequenceMatcher
from collections import defaultdict


class VulnerabilityDetector:
    def _strip_comments_and_docstrings(self, code: str) -> str:
        """
        Remove comments and docstrings from Python code.
        Returns code with comments and docstrings replaced by whitespace (to preserve line numbers).
        """
        import io, tokenize
        from token import COMMENT, STRING
        from io import StringIO
        output = []
        prev_toktype = tokenize.INDENT
        last_lineno = -1
        last_col = 0
        tokgen = tokenize.generate_tokens(StringIO(code).readline)
        for toktype, ttext, (slineno, scol), (elineno, ecol), ltext in tokgen:
            if slineno > last_lineno:
                last_col = 0
            if scol > last_col:
                output.append(" " * (scol - last_col))
            # Remove comments
            if toktype == COMMENT:
                output.append(" " * len(ttext))
            # Remove docstrings (multi-line strings not used as code)
            elif toktype == STRING:
                if prev_toktype == tokenize.INDENT or prev_toktype == tokenize.NEWLINE:
                    output.append(" " * len(ttext))
                else:
                    output.append(ttext)
            else:
                output.append(ttext)
            prev_toktype = toktype
            last_col = ecol
            last_lineno = elineno
        return "".join(output)
    
    def __init__(self, vulnerable_samples_dir: str):
        self.vulnerable_samples_dir = vulnerable_samples_dir
        self.cwe_database = self._load_cwe_database()
        self.vulnerability_patterns = self._initialize_patterns()
    
    def _load_cwe_database(self) -> Dict[str, List[Dict]]:
        """
        Load all vulnerable code samples from CWE directories.
        Returns a dictionary: {cwe_id: [list of vulnerable samples]}
        """
        cwe_db = {}
        
        if not os.path.exists(self.vulnerable_samples_dir):
            return cwe_db
        
        for cwe_folder in os.listdir(self.vulnerable_samples_dir):
            if not cwe_folder.startswith('CWE-'):
                continue
            
            cwe_id = cwe_folder.split('-')[1]
            cwe_path = os.path.join(self.vulnerable_samples_dir, cwe_folder)
            
            if not os.path.isdir(cwe_path):
                continue
            
            samples = []
            for filename in os.listdir(cwe_path):
                if filename.endswith('.py'):
                    file_path = os.path.join(cwe_path, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            code = f.read()
                            samples.append({
                                'code': code,
                                'filename': filename,
                                'cwe_id': cwe_id,
                                'cwe_name': self._get_cwe_name(cwe_id)
                            })
                    except Exception as e:
                        print(f"Error loading {file_path}: {e}")
            
            if samples:
                cwe_db[cwe_id] = samples
        
        return cwe_db
    
    def _get_cwe_name(self, cwe_id: str) -> str:
        """Map CWE IDs to their names."""
        # Normalize CWE ID - remove 'CWE-' prefix if present
        cwe_id = str(cwe_id).strip()
        if cwe_id.upper().startswith('CWE-'):
            cwe_id = cwe_id[4:]
        
        # Pad with leading zeros for consistency (CWEs are typically 3 digits)
        if cwe_id.isdigit() and len(cwe_id) < 3:
            cwe_id = cwe_id.zfill(3)
        
        cwe_names = {
            '020': 'Improper Input Validation',
            '022': 'Path Traversal',
            '078': 'OS Command Injection',
            '080': 'Improper Neutralization of Script-Related HTML Tags (Basic XSS)',
            '089': 'SQL Injection',
            '094': 'Code Injection',
            '095': 'Eval Injection',
            '116': 'Improper Encoding',
            '117': 'Log Injection',
            '193': 'Off-by-one Error',
            '200': 'Information Exposure',
            '252': 'Unchecked Return Value',
            '259': 'Hard-coded Password',
            '285': 'Improper Authorization',
            '295': 'Certificate Validation',
            '319': 'Cleartext Transmission',
            '321': 'Hard-coded Cryptographic Key',
            '326': 'Weak Encryption',
            '330': 'Weak Random',
            '331': 'Insufficient Entropy',
            '352': 'Cross-Site Request Forgery (CSRF)',
            '367': 'TOCTOU Race Condition',
            '414': 'Missing Lock Check',
            '425': 'Direct Request',
            '454': 'External Initialization',
            '477': 'Obsolete Function',
            '502': 'Deserialization',
            '522': 'Insufficiently Protected Credentials',
            '532': 'Insertion of Sensitive Information into Log File',
            '595': 'Sensitive Cookie',
            '605': 'Multiple Binds',
            '611': 'XXE',
            '614': 'Sensitive Cookie in HTTPS Session',
            '693': 'Missing Security Header',
            '703': 'Improper Check',
            '730': 'Regex DoS',
            '732': 'Incorrect Permission',
            '798': 'Hard-coded Credentials',
            '835': 'Infinite Loop',
            '937': 'Using Components with Known Vulnerabilities',
            '1004': 'Sensitive Cookie Without Secure Flag'
        }
        return cwe_names.get(cwe_id, 'Unknown Vulnerability')
    
    def _initialize_patterns(self) -> Dict[str, List[Dict]]:
        """
        Initialize vulnerability detection patterns for each CWE.
        These patterns are used for quick detection before AST analysis.
        """
        return {
            '089': [  # SQL Injection
                {'pattern': r'execute\(["\'].*%s.*["\']', 'description': 'String formatting in SQL query'},
                {'pattern': r'execute\(f["\']', 'description': 'f-string in SQL query'},
                {'pattern': r'execute\(.*\+.*\)', 'description': 'String concatenation in SQL query'},
            ],
            '022': [  # Path Traversal
                {'pattern': r'open\([^)]*request\.[^)]*\)', 'description': 'Direct user input in file open'},
                {'pattern': r'os\.remove\([^)]*request\.[^)]*\)', 'description': 'Direct user input in file delete'},
                {'pattern': r'os\.path\.join\([^)]*request\.[^)]*\)', 'description': 'Unvalidated path join'},
            ],
            '078': [  # Command Injection
                {'pattern': r'os\.system\([^)]*input\([^)]*\)', 'description': 'User input in os.system'},
                {'pattern': r'subprocess\.(run|call|Popen)\([^)]*\+', 'description': 'String concat in subprocess'},
                {'pattern': r'eval\(', 'description': 'Use of eval()'},
            ],
            '095': [  # Eval Injection
                {'pattern': r'eval\([^)]*input\([^)]*\)', 'description': 'User input in eval()'},
                {'pattern': r'exec\([^)]*input\([^)]*\)', 'description': 'User input in exec()'},
            ],
            '259': [  # Hard-coded Password
                {'pattern': r'password\s*=\s*["\'][^"\']+["\']', 'description': 'Hard-coded password'},
                {'pattern': r'passwd\s*=\s*["\'][^"\']+["\']', 'description': 'Hard-coded passwd'},
            ],
            '798': [  # Hard-coded Credentials
                {'pattern': r'api_key\s*=\s*["\'][^"\']+["\']', 'description': 'Hard-coded API key'},
                {'pattern': r'secret\s*=\s*["\'][^"\']+["\']', 'description': 'Hard-coded secret'},
            ],
            '502': [  # Deserialization
                {'pattern': r'pickle\.loads?\(', 'description': 'Unsafe deserialization with pickle'},
                {'pattern': r'yaml\.load\([^)]*Loader\s*=\s*yaml\.Loader', 'description': 'Unsafe YAML loading'},
            ],
            '611': [  # XXE
                {'pattern': r'etree\.parse\(.*resolve_entities\s*=\s*True', 'description': 'XML parsing with entities enabled'},
                {'pattern': r'xml\.etree\.ElementTree\.parse\(', 'description': 'Potentially unsafe XML parsing'},
            ],
            '326': [  # Weak Encryption
                {'pattern': r'DES\.new\(', 'description': 'Use of weak DES encryption'},
                {'pattern': r'MD5\(', 'description': 'Use of weak MD5 hash'},
            ],
            '330': [  # Weak Random
                {'pattern': r'random\.random\(\)', 'description': 'Use of weak random for security'},
                {'pattern': r'random\.randint\(', 'description': 'Use of weak random for security'},
            ],
        }
    
    def detect_vulnerabilities(self, generated_code: str) -> List[Dict]:
        """
        Main detection method that uses multiple strategies to identify vulnerabilities.
        Returns a list of detected vulnerabilities with CWE mapping.
        """
        detected_vulns = []
        
        # Strategy 1: Pattern-based detection
        pattern_vulns = self._pattern_based_detection(generated_code)
        detected_vulns.extend(pattern_vulns)
        
        # Strategy 2: AST-based detection
        ast_vulns = self._ast_based_detection(generated_code)
        detected_vulns.extend(ast_vulns)
        
        # Strategy 3: Similarity-based detection with CWE samples
        similarity_vulns = self._similarity_based_detection(generated_code)
        detected_vulns.extend(similarity_vulns)
        
        # Remove duplicates based on CWE ID and line number
        unique_vulns = self._deduplicate_vulnerabilities(detected_vulns)

        return unique_vulns
    

    def _pattern_based_detection(self, code: str) -> List[Dict]:
        """Detect vulnerabilities using AST-based semantic pattern matching for as many CWE types as possible."""
        vulns = []
        # Strip comments and docstrings (AST ignores them, but this adds extra safety)
        try:
            filtered_code = self._strip_comments_and_docstrings(code)
        except Exception:
            filtered_code = code  # If stripping fails, use original
        
        try:
            tree = ast.parse(filtered_code)
        except Exception:
            return vulns

        class PatternVisitor(ast.NodeVisitor):
            def __init__(self, outer):
                self.outer = outer
                self.vulns = []
                self.code = code  # Keep original for line numbers and snippets
                self.tainted = set()  # Track tainted variables
                self.sensitive_keywords = {'password', 'passwd', 'secret', 'token', 'auth', 'key', 'credential'}

            def is_tainted_expr(self, expr: ast.AST) -> bool:
                """Check if an expression contains tainted data."""
                if isinstance(expr, ast.Name):
                    return expr.id in self.tainted
                if isinstance(expr, ast.Call):
                    # Check if sanitizer - if so, not tainted
                    if self.is_sanitized(expr):
                        return False
                    
                    # Taint sources: input()
                    if isinstance(expr.func, ast.Name) and expr.func.id == 'input':
                        return True
                    
                    if isinstance(expr.func, ast.Attribute):
                        attr = expr.func
                        # Flask: request.args.get(), request.form.get(), request.cookies.get()
                        if isinstance(attr.value, ast.Attribute) and getattr(attr.value, 'attr', '') in {'args', 'form', 'cookies', 'headers', 'files', 'values', 'json'} and attr.attr == 'get':
                            return True
                        # Flask: request.get_json()
                        if isinstance(attr.value, ast.Name) and attr.value.id == 'request' and attr.attr in {'get_json'}:
                            return True
                        # Django: request.GET.get(), request.POST.get()
                        if isinstance(attr.value, ast.Attribute) and isinstance(attr.value.value, ast.Name):
                            if attr.value.value.id == 'request' and attr.value.attr in {'GET', 'POST'} and attr.attr == 'get':
                                return True
                    
                    # recursive check on args
                    return any(self.is_tainted_expr(a) for a in expr.args)
                if isinstance(expr, ast.BinOp):
                    return self.is_tainted_expr(expr.left) or self.is_tainted_expr(expr.right)
                if isinstance(expr, ast.JoinedStr):
                    for v in expr.values:
                        if isinstance(v, ast.FormattedValue) and self.is_tainted_expr(v.value):
                            return True
                    return False
                if isinstance(expr, ast.Attribute):
                    if isinstance(expr.value, ast.Name):
                        if expr.value.id in self.tainted:
                            return True
                        # Flask: request.json, request.data (direct access)
                        if expr.value.id == 'request' and expr.attr in {'json', 'data', 'args', 'form', 'GET', 'POST'}:
                            return True
                    return False
                if isinstance(expr, ast.Subscript):
                    # Flask: request.args['key'], Django: request.GET['key']
                    if isinstance(expr.value, ast.Attribute):
                        if isinstance(expr.value.value, ast.Name) and expr.value.value.id == 'request':
                            if expr.value.attr in {'args', 'form', 'cookies', 'headers', 'GET', 'POST'}:
                                return True
                    return self.is_tainted_expr(expr.value)
                return False

            def has_sensitive_name(self, expr: ast.AST) -> bool:
                """Check if expression involves sensitive variable names."""
                if isinstance(expr, ast.Name):
                    name_lower = expr.id.lower()
                    return any(keyword in name_lower for keyword in self.sensitive_keywords)
                if isinstance(expr, ast.Attribute):
                    attr_lower = expr.attr.lower()
                    return any(keyword in attr_lower for keyword in self.sensitive_keywords)
                if isinstance(expr, ast.Call):
                    return any(self.has_sensitive_name(a) for a in expr.args)
                if isinstance(expr, ast.BinOp):
                    return self.has_sensitive_name(expr.left) or self.has_sensitive_name(expr.right)
                if isinstance(expr, ast.JoinedStr):
                    for v in expr.values:
                        if isinstance(v, ast.FormattedValue) and self.has_sensitive_name(v.value):
                            return True
                    return False
                return False

            def is_sanitized(self, expr: ast.AST) -> bool:
                """Check if expression is wrapped in sanitization like repr, str.replace, escape."""
                if isinstance(expr, ast.Call):
                    if isinstance(expr.func, ast.Name) and expr.func.id in {'repr', 'str', 'escape', 'html_escape'}:
                        return True
                    if isinstance(expr.func, ast.Attribute) and expr.func.attr in {'replace', 'escape', 'encode'}:
                        return True
                return False

            def visit_Call(self, node):
                # SQL Injection: suspicious execute() calls
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
                    if node.args:
                        arg = node.args[0]
                        if isinstance(arg, ast.JoinedStr):
                            self.vulns.append(self.outer._make_vuln('089', node.lineno, 'Possible SQL injection: f-string in SQL query', self.code))
                        elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                            self.vulns.append(self.outer._make_vuln('089', node.lineno, 'Possible SQL injection: string formatting in SQL query', self.code))
                        elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                            self.vulns.append(self.outer._make_vuln('089', node.lineno, 'Possible SQL injection: string concatenation in SQL query', self.code))
                        elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == 'format':
                            self.vulns.append(self.outer._make_vuln('089', node.lineno, 'Possible SQL injection: .format() in SQL query', self.code))

                # Path Traversal: Only flag if tainted or without validation context
                # Removed generic checks - rely on taint-based detection in _ast_based_detection
                # This prevents false positives from safe internal file operations

                # Command Injection: os.system, subprocess with context awareness
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'system' and hasattr(node.func.value, 'id') and node.func.value.id == 'os':
                        # os.system is always dangerous if args are tainted or concatenated
                        for arg in node.args:
                            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                                self.vulns.append(self.outer._make_vuln('078', node.lineno, 'Command injection: string concatenation in os.system()', self.code, confidence=0.9))
                            elif isinstance(arg, ast.JoinedStr):
                                self.vulns.append(self.outer._make_vuln('078', node.lineno, 'Command injection: f-string in os.system()', self.code, confidence=0.9))
                            elif self.is_tainted_expr(arg):
                                self.vulns.append(self.outer._make_vuln('078', node.lineno, 'Command injection: tainted data in os.system()', self.code, confidence=0.85))
                    
                    if node.func.attr in {'popen', 'Popen', 'call', 'run'} and hasattr(node.func.value, 'id') and node.func.value.id == 'subprocess':
                        # Check for shell=True
                        shell_true = any(isinstance(kw, ast.keyword) and kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                        
                        if shell_true:
                            # shell=True is HIGH risk if args are tainted/concatenated
                            for arg in node.args:
                                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                                    self.vulns.append(self.outer._make_vuln('078', node.lineno, f'Command injection: string concatenation in subprocess.{node.func.attr}() with shell=True', self.code, confidence=0.95))
                                elif isinstance(arg, ast.JoinedStr):
                                    self.vulns.append(self.outer._make_vuln('078', node.lineno, f'Command injection: f-string in subprocess.{node.func.attr}() with shell=True', self.code, confidence=0.95))
                                elif self.is_tainted_expr(arg):
                                    self.vulns.append(self.outer._make_vuln('078', node.lineno, f'Command injection: tainted data in subprocess.{node.func.attr}() with shell=True', self.code, confidence=0.9))
                                elif not isinstance(arg, ast.List):
                                    # Non-list with shell=True
                                    self.vulns.append(self.outer._make_vuln('078', node.lineno, f'Potentially dangerous: subprocess.{node.func.attr}() with shell=True', self.code, confidence=0.6))
                        else:
                            # No shell=True: check if args are tainted or concatenated
                            for arg in node.args:
                                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                                    self.vulns.append(self.outer._make_vuln('078', node.lineno, f'Command injection: string concatenation in subprocess.{node.func.attr}()', self.code, confidence=0.8))
                                elif isinstance(arg, ast.JoinedStr):
                                    self.vulns.append(self.outer._make_vuln('078', node.lineno, f'Command injection: f-string in subprocess.{node.func.attr}()', self.code, confidence=0.8))
                                elif self.is_tainted_expr(arg):
                                    self.vulns.append(self.outer._make_vuln('078', node.lineno, f'Command injection: tainted data in subprocess.{node.func.attr}()', self.code, confidence=0.75))
                                elif isinstance(arg, ast.List):
                                    # Static list is lower risk, mark as LOW
                                    if all(isinstance(el, ast.Constant) for el in arg.elts):
                                        # All literal strings - mark as informational
                                        self.vulns.append(self.outer._make_vuln('078', node.lineno, f'Potentially dangerous API usage: subprocess.{node.func.attr}() with static list', self.code, confidence=0.3, severity='LOW'))
                                    else:
                                        # Mixed content in list
                                        self.vulns.append(self.outer._make_vuln('078', node.lineno, f'Possible command injection: subprocess.{node.func.attr}() with dynamic list', self.code, confidence=0.6))
                if isinstance(node.func, ast.Name) and node.func.id == 'eval':
                    self.vulns.append(self.outer._make_vuln('095', node.lineno, 'Use of eval()', self.code))
                if isinstance(node.func, ast.Name) and node.func.id == 'exec':
                    self.vulns.append(self.outer._make_vuln('095', node.lineno, 'Use of exec()', self.code))

                # Deserialization: pickle.loads, yaml.load (unsafe)
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in {'load', 'loads'} and hasattr(node.func.value, 'id') and node.func.value.id == 'pickle':
                        self.vulns.append(self.outer._make_vuln('502', node.lineno, 'Unsafe deserialization with pickle', self.code))
                    if node.func.attr == 'load' and hasattr(node.func.value, 'id') and node.func.value.id == 'yaml':
                        # Check for Loader argument
                        if not any((isinstance(kw, ast.keyword) and kw.arg == 'Loader' and getattr(kw.value, 'attr', '') == 'SafeLoader') for kw in node.keywords):
                            self.vulns.append(self.outer._make_vuln('502', node.lineno, 'Unsafe YAML loading (no SafeLoader)', self.code))

                # XXE: etree.parse with resolve_entities=True, xml.etree.ElementTree.parse
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'parse' and hasattr(node.func.value, 'id') and node.func.value.id == 'etree':
                        for kw in node.keywords:
                            if kw.arg == 'resolve_entities' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                self.vulns.append(self.outer._make_vuln('611', node.lineno, 'XML parsing with entities enabled', self.code))
                    if node.func.attr == 'parse' and hasattr(node.func.value, 'attr') and node.func.value.attr == 'ElementTree':
                        self.vulns.append(self.outer._make_vuln('611', node.lineno, 'Potentially unsafe XML parsing', self.code))

                # Weak Encryption/Hash: DES.new, MD5
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'new' and hasattr(node.func.value, 'id') and node.func.value.id == 'DES':
                        self.vulns.append(self.outer._make_vuln('326', node.lineno, 'Use of weak DES encryption', self.code))
                    if node.func.attr == 'md5':
                        self.vulns.append(self.outer._make_vuln('326', node.lineno, 'Use of weak MD5 hash', self.code))

                # Weak Random: random.random, random.randint
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in {'random', 'randint'} and hasattr(node.func.value, 'id') and node.func.value.id == 'random':
                        self.vulns.append(self.outer._make_vuln('330', node.lineno, 'Use of weak random for security', self.code))

                # Information Exposure: print, logging.info/debug/warning/error
                # Only flag when arguments are tainted or contain sensitive names
                if isinstance(node.func, ast.Name) and node.func.id == 'print':
                    for arg in node.args:
                        if self.is_tainted_expr(arg) or self.has_sensitive_name(arg):
                            self.vulns.append(self.outer._make_vuln('200', node.lineno, 'Possible information exposure via print() with sensitive/tainted data', self.code))
                            break
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in {'info', 'debug', 'warning', 'error'} and hasattr(node.func.value, 'id') and node.func.value.id == 'logging':
                        for arg in node.args:
                            if self.is_tainted_expr(arg) or self.has_sensitive_name(arg):
                                self.vulns.append(self.outer._make_vuln('200', node.lineno, f'Possible information exposure via logging.{node.func.attr}() with sensitive/tainted data', self.code))
                                break

                # Unchecked Return Value: os.system, subprocess.call/run
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in {'system', 'call', 'run'} and hasattr(node.func.value, 'id') and node.func.value.id in {'os', 'subprocess'}:
                        # If not assigned to a variable
                        if not hasattr(node, 'parent') or not isinstance(getattr(node, 'parent', None), ast.Assign):
                            self.vulns.append(self.outer._make_vuln('252', node.lineno, 'Unchecked return value from system call', self.code))

                # Log Injection: logging with tainted data in format strings
                # Only flag when tainted data is used without sanitization
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in {'info', 'debug', 'warning', 'error'} and hasattr(node.func.value, 'id') and node.func.value.id == 'logging':
                        for arg in node.args:
                            # Check for tainted data in format strings (f-strings, %, .format)
                            if isinstance(arg, ast.JoinedStr):  # f-string
                                for val in arg.values:
                                    if isinstance(val, ast.FormattedValue) and self.is_tainted_expr(val.value) and not self.is_sanitized(val.value):
                                        self.vulns.append(self.outer._make_vuln('117', node.lineno, 'Possible log injection: tainted data in f-string', self.code))
                                        break
                            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):  # % formatting
                                if self.is_tainted_expr(arg.right) and not self.is_sanitized(arg.right):
                                    self.vulns.append(self.outer._make_vuln('117', node.lineno, 'Possible log injection: tainted data in % format', self.code))
                            elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == 'format':  # .format()
                                for fmt_arg in arg.args:
                                    if self.is_tainted_expr(fmt_arg) and not self.is_sanitized(fmt_arg):
                                        self.vulns.append(self.outer._make_vuln('117', node.lineno, 'Possible log injection: tainted data in .format()', self.code))
                                        break

                # Infinite Loop: while True
                if isinstance(node.func, ast.Name) and node.func.id == 'range':
                    pass  # skip
                self.generic_visit(node)

            def visit_While(self, node):
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    self.vulns.append(self.outer._make_vuln('835', node.lineno, 'Possible infinite loop: while True', self.code))
                self.generic_visit(node)

            def visit_Assign(self, node):
                # Track tainted assignments
                if isinstance(node.targets[0], ast.Name):
                    if self.is_tainted_expr(node.value):
                        self.tainted.add(node.targets[0].id)
                    
                    # Hardcoded password, api_key, secret
                    var = node.targets[0].id.lower()
                    if var in {'password', 'passwd', 'api_key', 'secret'}:
                        if isinstance(node.value, ast.Str):
                            cwe = '259' if var in {'password', 'passwd'} else '798'
                            desc = f'Hard-coded {var.replace("_", " ")}'
                            self.vulns.append(self.outer._make_vuln(cwe, node.lineno, desc, self.code))
                self.generic_visit(node)

            def visit(self, node):
                # Attach parent pointers for context (for unchecked return value)
                for child in ast.iter_child_nodes(node):
                    child.parent = node
                super().visit(node)

        visitor = PatternVisitor(self)
        visitor.visit(tree)
        return visitor.vulns

    def _make_vuln(self, cwe_id, line_num, description, code, confidence=0.8, severity=None):
        return {
            'cwe_id': cwe_id,
            'cwe_name': self._get_cwe_name(cwe_id),
            'line_number': line_num,
            'description': description,
            'code_snippet': self._get_code_snippet(code, line_num),
            'severity': severity if severity else self._get_severity(cwe_id),
            'detection_method': 'semantic-pattern',
            'confidence': confidence
        }
    
    def _ast_based_detection(self, code: str) -> List[Dict]:
        """Detect vulnerabilities using AST analysis, with parameter taint, path traversal, exception handling, and YAML safe_load checks."""
        vulns = []
        try:
            tree = ast.parse(code)

            # --- Enhancement: Track function parameters as tainted for file/path sinks ---
            func_param_map = {}  # function_name -> set(param names)
            param_tainted = set()  # all parameter names in current scope
            param_validated = set()  # parameters validated by abspath/basename/whitelist
            param_in_try = set()  # parameters used in try/except
            func_defs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
            for func in func_defs:
                params = {a.arg for a in func.args.args}
                func_param_map[func.name] = params

            # Helper: find if a node is inside a Try block
            def is_in_try(node):
                while node:
                    if isinstance(node, ast.Try):
                        return True
                    node = getattr(node, 'parent', None)
                return False

            # Attach parent pointers for context
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    child.parent = node

            def extract_methods_from_decorator(dec: ast.AST) -> Set[str]:
                methods = set()
                target = None
                if isinstance(dec, ast.Call):
                    target = dec.func
                    for kw in dec.keywords:
                        if kw.arg == 'methods':
                            if isinstance(kw.value, (ast.List, ast.Tuple)):
                                for elt in kw.value.elts:
                                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                        methods.add(elt.value.upper())
                            elif isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                methods.add(kw.value.value.upper())
                elif isinstance(dec, ast.Attribute):
                    target = dec
                elif isinstance(dec, ast.Name):
                    target = dec

                if isinstance(target, ast.Attribute):
                    if target.attr.lower() in {'post', 'put', 'delete', 'patch'}:
                        methods.add(target.attr.upper())
                    if target.attr == 'route':
                        # route() defaults to GET if not specified
                        methods.add('GET')
                if isinstance(target, ast.Name):
                    if target.id.lower() in {'route', 'post', 'put', 'delete', 'patch'}:
                        methods.add(target.id.upper())

                return methods

            def methods_from_body(func: ast.FunctionDef) -> Set[str]:
                detected = set()
                for n in ast.walk(func):
                    if isinstance(n, ast.Compare):
                        if isinstance(n.left, ast.Attribute) and isinstance(n.left.value, ast.Name) and n.left.value.id == 'request' and n.left.attr == 'method':
                            for comp in n.comparators:
                                if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                                    method = comp.value.upper()
                                    if method in {'GET', 'POST', 'PUT', 'DELETE', 'PATCH'}:
                                        detected.add(method)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                        # Flask method-specific decorators like @bp.post
                        if n.func.attr.lower() in {'post', 'put', 'delete', 'patch'}:
                            detected.add(n.func.attr.upper())
                return detected

            def function_uses_form_data(func: ast.FunctionDef) -> bool:
                for n in ast.walk(func):
                    if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == 'request':
                        if n.attr in {'form', 'files', 'data', 'json', 'get_json', 'POST', 'body'}:
                            return True
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                        # request.form.get('x'), request.args.get('x') for form/query access
                        if isinstance(n.func.value, ast.Attribute) and isinstance(n.func.value.value, ast.Name):
                            if n.func.value.value.id == 'request' and n.func.value.attr in {'form', 'args', 'values', 'POST', 'GET'} and n.func.attr == 'get':
                                return True
                return False

            def has_csrf_decorator(func: ast.FunctionDef) -> Tuple[bool, bool]:
                """Return (protected, exempt)."""
                protected = False
                exempt = False
                for dec in func.decorator_list:
                    name = None
                    if isinstance(dec, ast.Name):
                        name = dec.id
                    elif isinstance(dec, ast.Attribute):
                        name = dec.attr
                    elif isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Name):
                            name = dec.func.id
                        elif isinstance(dec.func, ast.Attribute):
                            name = dec.func.attr
                    if not name:
                        continue
                    name_lower = name.lower()
                    if 'csrf_exempt' == name_lower or name_lower.endswith('csrf_exempt') or name_lower == 'exempt':
                        exempt = True
                    if 'csrf_protect' in name_lower or (name_lower.startswith('csrf') and 'exempt' not in name_lower) or ('csrf' in name_lower and 'exempt' not in name_lower):
                        protected = True
                return protected, exempt

            def is_false_constant(node_val: ast.AST) -> bool:
                return isinstance(node_val, ast.Constant) and node_val.value is False

            def is_true_constant(node_val: ast.AST) -> bool:
                return isinstance(node_val, ast.Constant) and node_val.value is True

            def header_name_from_target(target: ast.AST) -> Optional[str]:
                if isinstance(target, ast.Subscript):
                    if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                        return target.slice.value
                return None

            def is_auth_decorator(name_lower: str) -> bool:
                return name_lower in {
                    'login_required', 'permission_required', 'staff_member_required', 'admin_required',
                    'auth_required', 'requires_auth', 'jwt_required'
                } or name_lower.endswith('login_required') or name_lower.endswith('permission_required')

            def has_auth_decorator(func: ast.FunctionDef) -> bool:
                for dec in func.decorator_list:
                    name = None
                    if isinstance(dec, ast.Name):
                        name = dec.id
                    elif isinstance(dec, ast.Attribute):
                        name = dec.attr
                    elif isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Name):
                            name = dec.func.id
                        elif isinstance(dec.func, ast.Attribute):
                            name = dec.func.attr
                    if not name:
                        continue
                    if is_auth_decorator(name.lower()):
                        return True
                return False

            def has_inline_auth_checks(func: ast.FunctionDef) -> bool:
                for n in ast.walk(func):
                    # if not current_user.is_authenticated / request.user.is_authenticated / is_staff
                    if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not) and isinstance(n.operand, ast.Attribute):
                        attr = n.operand
                        if isinstance(attr.value, ast.Attribute):
                            if getattr(attr.value, 'attr', '') in {'user', 'current_user'} and attr.attr in {'is_authenticated', 'is_staff', 'is_admin'}:
                                return True
                        if isinstance(attr.value, ast.Name) and attr.value.id in {'current_user', 'user', 'request'} and attr.attr in {'is_authenticated', 'is_staff', 'is_admin'}:
                            return True
                    if isinstance(n, ast.Compare):
                        if isinstance(n.left, ast.Attribute) and n.left.attr in {'is_authenticated', 'is_staff', 'is_admin'}:
                            if any(isinstance(comp, ast.Constant) and comp.value is False for comp in n.comparators):
                                return True
                    # explicit allow/deny checks e.g., if role != 'admin'
                    if isinstance(n, ast.Compare):
                        if isinstance(n.left, ast.Name) and n.left.id.lower() in {'role', 'user_role', 'permission'}:
                            return True
                return False

            def get_route_paths(func: ast.FunctionDef) -> Set[str]:
                paths = set()
                for dec in func.decorator_list:
                    call = dec if isinstance(dec, ast.Call) else None
                    target = dec.func if isinstance(dec, ast.Call) else dec
                    if isinstance(target, ast.Attribute) and target.attr in {'route', 'get', 'post', 'put', 'delete', 'patch'} and call and call.args:
                        first = call.args[0]
                        if isinstance(first, ast.Constant) and isinstance(first.value, str):
                            paths.add(first.value)
                    if isinstance(target, ast.Name) and target.id in {'route', 'get', 'post', 'put', 'delete', 'patch'} and call and call.args:
                        first = call.args[0]
                        if isinstance(first, ast.Constant) and isinstance(first.value, str):
                            paths.add(first.value)
                return paths

            def is_sensitive_operation(node: ast.AST) -> bool:
                # Heuristics: user/account/admin/payment data access, file writes/deletes, config/privilege changes
                sensitive_names = {'user', 'account', 'admin', 'payment', 'invoice', 'token', 'secret', 'config', 'credential'}
                critical_paths = {'/etc', '/var', '/config', '/admin', '/secrets', '/root'}
                if isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name) and node.value.id.lower() in sensitive_names:
                        return True
                if isinstance(node, ast.Name) and node.id.lower() in sensitive_names:
                    return True
                if isinstance(node, ast.Call):
                    func_name = self._get_func_name(node)
                    # file write/delete/privilege operations
                    if func_name in {'os.remove', 'os.unlink', 'os.rmdir', 'shutil.rmtree', 'open'}:
                        if node.args:
                            arg0 = node.args[0]
                            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                                for p in critical_paths:
                                    if arg0.value.startswith(p):
                                        return True
                        # open with write/append modes
                        if func_name == 'open' and len(node.args) >= 2:
                            mode = node.args[1]
                            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(m in mode.value for m in ['w', 'a', '+']):
                                return True
                    if func_name and any(key in func_name.lower() for key in ['permission', 'role', 'auth', 'privilege', 'config', 'admin']):
                        return True
                if isinstance(node, ast.Assign):
                    # config/privilege toggles
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id.upper() in {'DEBUG', 'SECRET_KEY', 'ADMIN', 'ALLOW_DEBUG', 'ALLOW_ADMIN'}:
                            return True
                        if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                            key = target.slice.value.lower()
                            if any(k in key for k in ['admin', 'debug', 'auth', 'secret', 'token']):
                                return True
                return False

            def is_unsafe_header_value(header: str, val_node: ast.AST) -> bool:
                if not isinstance(val_node, ast.Constant) or not isinstance(val_node.value, str):
                    return False
                value = val_node.value.strip().lower()
                header_lower = header.lower()
                if header_lower == 'x-frame-options':
                    return value in {'', 'allowall', 'allow-from *', 'allow-from', '*'}
                if header_lower == 'content-security-policy':
                    return value == '' or value == '*' or 'default-src *' in value
                if header_lower == 'strict-transport-security':
                    return 'max-age' not in value or value.startswith('max-age=0')
                return False

            # Collect validated params (os.path.abspath, os.path.basename, custom validate_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in {'abspath', 'basename'} and node.args:
                            if isinstance(node.args[0], ast.Name):
                                param_validated.add(node.args[0].id)
                    elif isinstance(node.func, ast.Name):
                        if node.func.id in {'validate_path', 'is_safe_path'} and node.args:
                            if isinstance(node.args[0], ast.Name):
                                param_validated.add(node.args[0].id)

            # CSRF protection checks for web endpoints (Flask/Django-style)
            for func in func_defs:
                is_endpoint = False
                methods = set()
                route_paths = get_route_paths(func)

                # Decorators: Flask @app.route / @bp.route / @bp.post
                for dec in func.decorator_list:
                    methods.update(extract_methods_from_decorator(dec))
                    if isinstance(dec, (ast.Call, ast.Attribute, ast.Name)):
                        target = dec.func if isinstance(dec, ast.Call) else dec
                        if isinstance(target, ast.Attribute) and target.attr in {'route', 'post', 'put', 'delete', 'patch'}:
                            is_endpoint = True
                        if isinstance(target, ast.Name) and target.id in {'route', 'post', 'put', 'delete', 'patch'}:
                            is_endpoint = True

                # Django-style view: first arg named request implies endpoint
                if func.args.args and func.args.args[0].arg == 'request':
                    is_endpoint = True

                methods.update(methods_from_body(func))
                uses_state_change = bool(methods & {'POST', 'PUT', 'DELETE', 'PATCH'})

                if not is_endpoint or not uses_state_change:
                    continue

                # Heuristic: processes form/body data
                if not function_uses_form_data(func):
                    continue

                protected, exempt = has_csrf_decorator(func)

                if exempt or not protected:
                    vulns.append({
                        'cwe_id': '352',
                        'cwe_name': self._get_cwe_name('352'),
                        'line_number': func.lineno,
                        'description': 'Endpoint handling state-changing requests without visible CSRF protection',
                        'code_snippet': self._get_code_snippet(code, func.lineno),
                        'severity': 'MEDIUM',
                        'detection_method': 'ast-framework',
                        'confidence': 0.45
                    })

                # Authorization / access control checks (CWE-285)
                sensitive = False
                for n in ast.walk(func):
                    if is_sensitive_operation(n):
                        sensitive = True
                        break

                if sensitive:
                    has_auth = has_auth_decorator(func) or has_inline_auth_checks(func)
                    if not has_auth:
                        vulns.append({
                            'cwe_id': '285',
                            'cwe_name': self._get_cwe_name('285'),
                            'line_number': func.lineno,
                            'description': 'Endpoint performs sensitive operations without authentication/authorization checks',
                            'code_snippet': self._get_code_snippet(code, func.lineno),
                            'severity': 'HIGH',
                            'detection_method': 'ast-framework',
                            'confidence': 0.55
                        })

                # Public admin/debug/config paths without auth
                risky_paths = {'/admin', '/admin/', '/debug', '/debug/', '/config', '/config/'}
                if route_paths and (route_paths & risky_paths):
                    has_auth = has_auth_decorator(func) or has_inline_auth_checks(func)
                    if not has_auth:
                        vulns.append({
                            'cwe_id': '285',
                            'cwe_name': self._get_cwe_name('285'),
                            'line_number': func.lineno,
                            'description': 'Admin/debug/config endpoint exposed without auth checks',
                            'code_snippet': self._get_code_snippet(code, func.lineno),
                            'severity': 'HIGH',
                            'detection_method': 'ast-framework',
                            'confidence': 0.6
                        })

            # Main pass: check for file/path sinks and YAML safe_load
            for node in ast.walk(tree):
                # Track current function parameters
                if isinstance(node, ast.FunctionDef):
                    param_tainted = {a.arg for a in node.args.args}

                # Path Traversal: open() with parameter, not validated
                if isinstance(node, ast.Call):
                    # open(filename)
                    if (isinstance(node.func, ast.Name) and node.func.id == 'open' and node.args):
                        arg = node.args[0]
                        if isinstance(arg, ast.Name) and arg.id in param_tainted and arg.id not in param_validated:
                            line_num = node.lineno
                            vulns.append({
                                'cwe_id': '022',
                                'cwe_name': self._get_cwe_name('022'),
                                'line_number': line_num,
                                'description': f'Function parameter "{arg.id}" used in open() without validation (possible path traversal)',
                                'code_snippet': self._get_code_snippet(code, line_num),
                                'severity': self._get_severity('022'),
                                'detection_method': 'ast-param',
                                'confidence': 0.7
                            })
                    # YAML safe_load(filename) with parameter
                    if (isinstance(node.func, ast.Attribute) and node.func.attr == 'safe_load' and node.args):
                        arg = node.args[0]
                        if isinstance(arg, ast.Name) and arg.id in param_tainted:
                            line_num = node.lineno
                            vulns.append({
                                'cwe_id': '502',
                                'cwe_name': self._get_cwe_name('502'),
                                'line_number': line_num,
                                'description': f'YAML safe_load() used on external parameter "{arg.id}"; safe_load is safer but still risky if input is untrusted.',
                                'code_snippet': self._get_code_snippet(code, line_num),
                                'severity': 'LOW',
                                'detection_method': 'ast-param',
                                'confidence': 0.5
                            })

                # Exception Handling: open() or yaml.safe_load() not in try/except
                if isinstance(node, ast.Call):
                    should_check_exception = False
                    call_name = None
                    
                    if isinstance(node.func, ast.Name) and node.func.id == 'open':
                        should_check_exception = True
                        call_name = 'open'
                    elif isinstance(node.func, ast.Attribute) and node.func.attr == 'safe_load':
                        should_check_exception = True
                        call_name = 'safe_load'
                    
                    if should_check_exception and node.args:
                        arg = node.args[0]
                        is_external = False
                        
                        # Check if argument is external
                        if isinstance(arg, ast.Name):
                            # Check if it's a function parameter
                            if arg.id in param_tainted:
                                is_external = True
                        elif isinstance(arg, ast.Call):
                            # Check if it's a direct call to input() or request.*.get()
                            if isinstance(arg.func, ast.Name) and arg.func.id == 'input':
                                is_external = True
                            elif isinstance(arg.func, ast.Attribute):
                                if isinstance(arg.func.value, ast.Attribute):
                                    if getattr(arg.func.value, 'attr', '') in {'args', 'form', 'cookies', 'headers'} and arg.func.attr == 'get':
                                        is_external = True
                                elif isinstance(arg.func.value, ast.Name) and arg.func.value.id == 'request':
                                    if arg.func.attr in {'get_json', 'json', 'data'}:
                                        is_external = True
                        elif isinstance(arg, ast.Subscript):
                            # Check for request.args['key'] pattern
                            if isinstance(arg.value, ast.Attribute):
                                if isinstance(arg.value.value, ast.Name) and arg.value.value.id == 'request':
                                    if arg.value.attr in {'args', 'form', 'GET', 'POST'}:
                                        is_external = True
                        # If it's a constant string, it's internal - don't flag
                        elif isinstance(arg, ast.Constant):
                            is_external = False
                        
                        # Only report if input is external and not in try/except
                        if is_external and not is_in_try(node):
                            line_num = node.lineno
                            vulns.append({
                                'cwe_id': '703',
                                'cwe_name': self._get_cwe_name('703'),
                                'line_number': line_num,
                                'description': f'No exception handling for {call_name}() with external input (CWE-703)',
                                'code_snippet': self._get_code_snippet(code, line_num),
                                'severity': 'LOW',
                                'detection_method': 'ast-except',
                                'confidence': 0.6
                            })

            # Cookie security flags and session config
            session_cookie_keys = {
                'SESSION_COOKIE_SECURE', 'SESSION_COOKIE_HTTPONLY', 'SESSION_COOKIE_SAMESITE'
            }
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'set_cookie':
                    kw_map = {kw.arg: kw.value for kw in node.keywords if kw.arg}
                    secure_kw = kw_map.get('secure')
                    httponly_kw = kw_map.get('httponly')
                    line_num = node.lineno

                    if secure_kw is None or is_false_constant(secure_kw):
                        vulns.append({
                            'cwe_id': '614',
                            'cwe_name': self._get_cwe_name('614'),
                            'line_number': line_num,
                            'description': 'Cookie set without Secure flag',
                            'code_snippet': self._get_code_snippet(code, line_num),
                            'severity': 'MEDIUM',
                            'detection_method': 'ast-framework',
                            'confidence': 0.5
                        })
                    if httponly_kw is None or is_false_constant(httponly_kw):
                        vulns.append({
                            'cwe_id': '1004',
                            'cwe_name': self._get_cwe_name('1004'),
                            'line_number': line_num,
                            'description': 'Cookie set without HttpOnly flag',
                            'code_snippet': self._get_code_snippet(code, line_num),
                            'severity': 'MEDIUM',
                            'detection_method': 'ast-framework',
                            'confidence': 0.5
                        })

                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        config_key = None
                        if isinstance(target, ast.Subscript):
                            if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                                if isinstance(target.value, ast.Attribute) and target.value.attr == 'config':
                                    config_key = target.slice.value
                        if isinstance(target, ast.Name):
                            config_key = target.id

                        if config_key in session_cookie_keys:
                            if is_false_constant(node.value):
                                vulns.append({
                                    'cwe_id': '614',
                                    'cwe_name': self._get_cwe_name('614'),
                                    'line_number': node.lineno,
                                    'description': f'{config_key} is disabled or set to False',
                                    'code_snippet': self._get_code_snippet(code, node.lineno),
                                    'severity': 'MEDIUM',
                                    'detection_method': 'ast-config',
                                    'confidence': 0.45
                                })
                            elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and node.value.value.lower() in {'none', 'false'}:
                                vulns.append({
                                    'cwe_id': '614',
                                    'cwe_name': self._get_cwe_name('614'),
                                    'line_number': node.lineno,
                                    'description': f'{config_key} is configured insecurely',
                                    'code_snippet': self._get_code_snippet(code, node.lineno),
                                    'severity': 'MEDIUM',
                                    'detection_method': 'ast-config',
                                    'confidence': 0.45
                                })

            # Security headers
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        header = header_name_from_target(target)
                        if not header:
                            continue
                        if header.lower() in {'x-frame-options', 'content-security-policy', 'strict-transport-security'}:
                            if is_unsafe_header_value(header, node.value):
                                vulns.append({
                                    'cwe_id': '693',
                                    'cwe_name': self._get_cwe_name('693'),
                                    'line_number': node.lineno,
                                    'description': f'Insecure value for security header {header}',
                                    'code_snippet': self._get_code_snippet(code, node.lineno),
                                    'severity': 'LOW',
                                    'detection_method': 'ast-config',
                                    'confidence': 0.4
                                })

            # Existing checks: dangerous calls, hardcoded secrets
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    v = self._check_dangerous_call(node, code)
                    if v:
                        vulns.append(v)
                elif isinstance(node, ast.Assign):
                    v = self._check_hardcoded_secrets(node, code)
                    if v:
                        vulns.append(v)

            # Existing taint analysis
            taint_vulns = self._taint_analysis(tree, code)
            vulns.extend(taint_vulns)
        except SyntaxError:
            pass

        return vulns

    def _taint_analysis(self, tree: ast.AST, code: str) -> List[Dict]:
        vulns: List[Dict] = []

        tainted = set()
        sanitized = set()  # Track sanitized variables
        
        # Inter-procedural analysis: track which parameters flow into sinks
        # Format: {func_name: {param_index: (cwe_id, sink_desc)}}
        func_param_sinks = defaultdict(dict)
        
        # List of sanitizer functions that clear taint
        sanitizer_funcs = {
            'escape', 'html_escape', 'html.escape', 'xml.escape',
            'urllib.parse.quote', 'urllib.parse.quote_plus',
            'bleach.clean', 'markupsafe.escape', 'jinja2.escape',
            'repr', 'str', 'int', 'float',  # Type conversions can sanitize
            'sanitize', 'clean', 'validate'  # Common custom sanitizers
        }
        
        def is_sanitizer_call(expr: ast.AST) -> bool:
            """Check if expression is a sanitizer function call."""
            if isinstance(expr, ast.Call):
                if isinstance(expr.func, ast.Name) and expr.func.id in sanitizer_funcs:
                    return True
                if isinstance(expr.func, ast.Attribute):
                    func_name = f"{getattr(expr.func.value, 'id', '')}.{expr.func.attr}"
                    if func_name in sanitizer_funcs or expr.func.attr in sanitizer_funcs:
                        return True
                    # Check for string methods that sanitize: .replace(), .encode()
                    if expr.func.attr in {'replace', 'encode', 'translate'}:
                        return True
            return False

        def is_escape_bypass(expr: ast.AST) -> bool:
            """Return True if expression explicitly disables HTML escaping (mark_safe / Markup / safe filter)."""
            if isinstance(expr, ast.Call):
                fname = None
                if isinstance(expr.func, ast.Name):
                    fname = expr.func.id
                elif isinstance(expr.func, ast.Attribute):
                    base = getattr(expr.func.value, 'id', '')
                    fname = f"{base}.{expr.func.attr}" if base else expr.func.attr
                if fname:
                    fname_lower = fname.lower()
                    if fname_lower in {'mark_safe', 'markupsafe.markup', 'jinja2.markup', 'markup'}:
                        return True
            # Jinja/Django `|safe` filter is not directly visible in Python AST; best-effort only
            return False
        
        def is_tainted_expr(expr: ast.AST) -> bool:
            if isinstance(expr, ast.Name):
                return expr.id in tainted and expr.id not in sanitized
            if isinstance(expr, ast.Call):
                # Check if this is a sanitizer call - if so, not tainted
                if is_sanitizer_call(expr):
                    return False
                
                # Taint sources
                if isinstance(expr.func, ast.Name) and expr.func.id == 'input':
                    return True
                
                if isinstance(expr.func, ast.Attribute):
                    attr = expr.func
                    # Flask: request.args.get(), request.form.get(), request.args['key'], request.form['key']
                    if isinstance(attr.value, ast.Attribute):
                        if getattr(attr.value, 'attr', '') in {'args', 'form', 'cookies', 'headers', 'files', 'values', 'json'} and attr.attr == 'get':
                            return True
                    # Flask: request.json, request.data
                    if isinstance(attr.value, ast.Name) and attr.value.id == 'request':
                        if attr.attr in {'json', 'data', 'get_json'}:
                            return True
                    # Django: request.GET.get(), request.POST.get()
                    if isinstance(attr.value, ast.Attribute) and isinstance(attr.value.value, ast.Name):
                        if attr.value.value.id == 'request' and attr.value.attr in {'GET', 'POST'} and attr.attr == 'get':
                            return True
                
                # recursive check on args
                return any(is_tainted_expr(a) for a in expr.args)
            if isinstance(expr, ast.BinOp):
                return is_tainted_expr(expr.left) or is_tainted_expr(expr.right)
            if isinstance(expr, ast.JoinedStr):
                for v in expr.values:
                    if isinstance(v, ast.FormattedValue) and is_tainted_expr(v.value):
                        return True
                return False
            if isinstance(expr, ast.Attribute):
                if isinstance(expr.value, ast.Name):
                    if expr.value.id in tainted and expr.value.id not in sanitized:
                        return True
                    # Flask: request.args, request.form (direct access)
                    if expr.value.id == 'request' and expr.attr in {'args', 'form', 'json', 'data', 'GET', 'POST'}:
                        return True
                return False
            if isinstance(expr, ast.Subscript):
                # Flask: request.args['key'], Django: request.GET['key']
                if isinstance(expr.value, ast.Attribute):
                    if isinstance(expr.value.value, ast.Name) and expr.value.value.id == 'request':
                        if expr.value.attr in {'args', 'form', 'cookies', 'headers', 'GET', 'POST'}:
                            return True
                return is_tainted_expr(expr.value)
            if isinstance(expr, ast.Constant):
                return False
            return False

        # First pass: mark directly tainted assignments
        sql_keywords = {"select", "insert", "update", "delete", "from", "where", "values"}
        def node_contains_sql_literals(n: ast.AST) -> bool:
            if isinstance(n, ast.JoinedStr):
                return any(isinstance(v, ast.Constant) and isinstance(v.value, str) and any(kw in v.value.lower() for kw in sql_keywords) for v in n.values)
            if isinstance(n, ast.BinOp):
                parts = []
                if isinstance(n.left, ast.Constant) and isinstance(n.left.value, str):
                    parts.append(n.left.value)
                if isinstance(n.right, ast.Constant) and isinstance(n.right.value, str):
                    parts.append(n.right.value)
                joined = " ".join(parts).lower()
                return any(kw in joined for kw in sql_keywords)
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                return any(kw in n.value.lower() for kw in sql_keywords)
            return False

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                value = node.value
                # Check if value is sanitized
                is_sanitized = is_sanitizer_call(value)
                
                direct_taint = is_tainted_expr(value)
                # Only mark as tainted if the value actually comes from tainted input
                if direct_taint and not is_sanitized:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            tainted.add(t.id)
                            # Remove from sanitized if it was there
                            sanitized.discard(t.id)
                elif is_sanitized:
                    # Mark as sanitized (clears taint)
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            sanitized.add(t.id)
                            tainted.discard(t.id)

        # Inter-procedural pass: Analyze function definitions to track param->sink flows
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_name = node.name
                param_names = [arg.arg for arg in node.args.args]
                local_tainted = set(param_names)  # All params start as potentially tainted
                
                # Walk through function body to find sinks
                for body_node in ast.walk(node):
                    if isinstance(body_node, ast.Call):
                        func_call_name = self._get_func_name(body_node)
                        # Use the sink detection function we'll define below
                        if func_call_name:
                            # Check if any parameter flows into this call
                            for arg_idx, arg in enumerate(body_node.args):
                                if isinstance(arg, ast.Name) and arg.id in param_names:
                                    # This parameter flows into a function call
                                    param_idx = param_names.index(arg.id)
                                    # Store for later inter-procedural checks
                                    if func_name not in func_param_sinks:
                                        func_param_sinks[func_name] = {}
                                    if param_idx not in func_param_sinks[func_name]:
                                        func_param_sinks[func_name][param_idx] = []
                                    func_param_sinks[func_name][param_idx].append(func_call_name)

        # Second pass: detect sinks using tainted vars
        def get_cwe_for_sink(func_name: str) -> tuple:
            """Return (cwe_id, description) for sink."""
            if func_name.endswith('.execute') or func_name == 'execute':
                return ('089', 'SQL Injection')
            if func_name in {'os.system', 'subprocess.run', 'subprocess.call', 'subprocess.Popen'}:
                return ('078', 'Command Injection')
            if func_name in {'open'} or func_name.endswith('.open'):
                return ('022', 'Path Traversal')
            # Template rendering sinks (XSS potential)
            if func_name in {'render_template', 'render_template_string', 'render', 'render_to_string'}:
                return ('080', 'XSS via template')
            if func_name.endswith('.render') or func_name == 'template.render':
                return ('080', 'XSS via template rendering')
            # HTTP response sinks (XSS potential)
            if func_name in {'Response', 'HttpResponse', 'make_response', 'jsonify'}:
                return ('080', 'XSS via HTTP response')
            if func_name == 'send' or func_name.endswith('.send'):
                return ('080', 'XSS via send')
            return ('', '')

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                cwe_info = get_cwe_for_sink(func_name)
                if not cwe_info[0]:
                    continue
                cwe_id, sink_desc = cwe_info
                # Any tainted argument or tainted string construction flows into sink
                tainted_arg = any(is_tainted_expr(arg) for arg in node.args)
                # Special case: cursor.execute(query) where query built insecurely
                if node.args:
                    arg0 = node.args[0]
                    if not tainted_arg:
                        if isinstance(arg0, ast.Name) and arg0.id in tainted:
                            tainted_arg = True
                        # Heuristic: SQL built via string ops passed directly
                        if cwe_id == '089' and (isinstance(arg0, ast.JoinedStr) or isinstance(arg0, ast.BinOp)):
                            if node_contains_sql_literals(arg0):
                                tainted_arg = True
                # subprocess with shell=True is risky even without taint
                if func_name.startswith('subprocess.'):
                    for kw in node.keywords:
                        if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            if any(is_tainted_expr(arg) for arg in node.args):
                                cwe_id = '078'
                                tainted_arg = True
                if tainted_arg:
                    line_num = node.lineno
                    severity = self._get_severity(cwe_id)
                    confidence = 0.8
                    desc = f'{sink_desc}: Tainted data flows into {func_name}()'

                    if cwe_id == '080':
                        bypass_used = any(is_escape_bypass(arg) for arg in node.args)
                        template_sinks = {'render_template', 'render_template_string', 'render', 'render_to_string', 'template.render'}
                        if func_name.endswith('.render'):
                            template_sinks.add(func_name)
                        if bypass_used:
                            severity = 'HIGH'
                            confidence = 0.9
                            desc = f'{sink_desc}: Escape bypass (mark_safe/Markup) with tainted data in {func_name}()'
                        else:
                            if func_name in template_sinks:
                                severity = 'LOW'  # auto-escape defaults; still report but low
                                confidence = 0.65
                            else:
                                severity = 'MEDIUM'  # direct HTTP responses
                                confidence = 0.75
                    vulns.append({
                        'cwe_id': cwe_id,
                        'cwe_name': self._get_cwe_name(cwe_id),
                        'line_number': line_num,
                        'description': desc,
                        'code_snippet': self._get_code_snippet(code, line_num),
                        'severity': severity,
                        'detection_method': 'ast-taint',
                        'confidence': confidence
                    })

        # Third pass: Inter-procedural analysis - check calls to user-defined functions
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    called_func_name = node.func.id
                    # Check if this is a function we analyzed
                    if called_func_name in func_param_sinks:
                        # Check each argument for taint
                        for arg_idx, arg in enumerate(node.args):
                            if is_tainted_expr(arg):
                                # This tainted argument flows into a sink via the called function
                                if arg_idx in func_param_sinks[called_func_name]:
                                    sink_funcs = func_param_sinks[called_func_name][arg_idx]
                                    # Determine CWE based on sink functions
                                    for sink_func in sink_funcs:
                                        cwe_info = get_cwe_for_sink(sink_func)
                                        if cwe_info[0]:
                                            cwe_id, sink_desc = cwe_info
                                            line_num = node.lineno
                                            vulns.append({
                                                'cwe_id': cwe_id,
                                                'cwe_name': self._get_cwe_name(cwe_id),
                                                'line_number': line_num,
                                                'description': f'{sink_desc}: Tainted data flows into {called_func_name}() which calls {sink_func}()',
                                                'code_snippet': self._get_code_snippet(code, line_num),
                                                'severity': self._get_severity(cwe_id),
                                                'detection_method': 'ast-interprocedural',
                                                'confidence': 0.75
                                            })
                                            break  # Only report once per argument

        return vulns
    
    def _check_dangerous_call(self, node: ast.Call, code: str) -> Dict:
        """Check if a function call is potentially dangerous."""
        dangerous_funcs = {
            'eval': '095',
            'exec': '094',
            'compile': '094',
            'pickle.loads': '502',
            'pickle.load': '502',
            'yaml.load': '502',
            'os.system': '078',
            'subprocess.call': '078',
            'subprocess.run': '078',
        }
        
        func_name = self._get_func_name(node)
        
        if func_name in dangerous_funcs:
            cwe_id = dangerous_funcs[func_name]
            line_num = node.lineno
            
            return {
                'cwe_id': cwe_id,
                'cwe_name': self._get_cwe_name(cwe_id),
                'line_number': line_num,
                'description': f'Dangerous use of {func_name}()',
                'code_snippet': self._get_code_snippet(code, line_num),
                'severity': self._get_severity(cwe_id),
                'detection_method': 'ast',
                'confidence': 0.85
            }
        
        return None
    
    def _check_hardcoded_secrets(self, node: ast.Assign, code: str) -> Dict:
        """Check for hard-coded passwords, keys, or secrets."""
        secret_keywords = ['password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey', 'token', 'auth']
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                if any(keyword in var_name for keyword in secret_keywords):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 0:  # Non-empty string
                            cwe_id = '798' if 'key' in var_name or 'token' in var_name else '259'
                            
                            return {
                                'cwe_id': cwe_id,
                                'cwe_name': self._get_cwe_name(cwe_id),
                                'line_number': node.lineno,
                                'description': f'Hard-coded credential in variable "{target.id}"',
                                'code_snippet': self._get_code_snippet(code, node.lineno),
                                'severity': 'HIGH',
                                'detection_method': 'ast',
                                'confidence': 0.9
                            }
        
        return None
    
    def _get_func_name(self, node: ast.Call) -> str:
        """Extract function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            # nested attribute like cursor.execute
            try:
                base = node.func.value
                parts = []
                while isinstance(base, ast.Attribute):
                    parts.append(base.attr)
                    base = base.value
                if isinstance(base, ast.Name):
                    parts.append(base.id)
                    parts = list(reversed(parts))
                    parts.append(node.func.attr)
                    return '.'.join(parts)
            except Exception:
                return node.func.attr
        return ""

    def _contains_relevant_sink(self, cwe_id: str, code: str) -> bool:
        """Check if code contains sink substrings relevant to a CWE.

        Normalizes the CWE ID to a 3-digit string and searches for
        CWE-specific sink indicators via simple substring matching.
        Returns True if any sink substring is found, else False.
        """
        # Strip comments and docstrings to avoid false positives from commented code
        try:
            code = self._strip_comments_and_docstrings(code)
        except Exception:
            pass  # If stripping fails, continue with original code
        
        cid = str(cwe_id).strip()
        if cid.upper().startswith('CWE-'):
            cid = cid[4:]
        if cid.isdigit() and len(cid) < 3:
            cid = cid.zfill(3)

        sinks: Dict[str, List[str]] = {
            # SQL Injection
            '089': ['cursor.execute', 'execute(', 'select ', 'insert ', 'update ', 'delete '],
            # Path Traversal
            '022': ['open(', 'os.remove(', 'os.path.join', 'shutil.rmtree', 'pathlib.Path('],
            # OS Command Injection
            '078': ['os.system(', 'subprocess.run', 'subprocess.call', 'subprocess.Popen', 'shell=True'],
            # Code/Eval Injection
            '094': ['exec(', 'compile('],
            '095': ['eval(', 'exec('],
            # Deserialization
            '502': ['pickle.load', 'pickle.loads', 'yaml.load(', 'jsonpickle.decode'],
            # XXE
            '611': ['etree.parse(', 'xml.etree.ElementTree.parse', 'resolve_entities=True', 'XMLParser('],
            # Weak Crypto / Hash
            '326': ['DES.new(', 'MD5(', 'md5(', 'sha1('],
            # Weak Random
            '330': ['random.random(', 'random.randint('],
            # Hard-coded credentials/passwords (simple sinks)
            '259': ['password', 'passwd', 'pwd'],
            '798': ['api_key', 'apikey', 'secret', 'token'],
            # Improper Exception Handling indicators (generic IO/API calls)
            '703': ['open(', 'yaml.safe_load(', 'requests.get(', 'requests.post('],
            # Permissions
            '732': ['os.chmod(', 'chmod('],
            # Regex DoS (presence of regex usage)
            '730': ['re.compile(', 're.search(', 're.match('],
        }

        subs = sinks.get(cid)
        # If no mapping exists for this CWE, don't block upstream logic
        if not subs:
            return True
        lowered = code.lower()
        return any(sub.lower() in lowered for sub in subs)

    def _validate_similarity_hit(self, cwe_id: str, snippet_code: str) -> bool:
        """Validate a similarity-based hit by checking actual sinks and AST.

        - First, ensure the code contains relevant sink indicators for the CWE.
        - Then, run AST-based detection on the snippet.
        - Return True if any AST finding matches the CWE ID.
        """
        cid = str(cwe_id).strip()
        if cid.upper().startswith('CWE-'):
            cid = cid[4:]
        if cid.isdigit() and len(cid) < 3:
            cid = cid.zfill(3)

        if not self._contains_relevant_sink(cid, snippet_code):
            return False

        ast_vulns = self._ast_based_detection(snippet_code)
        return any(v.get('cwe_id') == cid for v in ast_vulns)
    
    def _similarity_based_detection(self, generated_code: str) -> List[Dict]:
        """Detect vulnerabilities by comparing with known vulnerable samples."""
        vulns = []
        
        for cwe_id, samples in self.cwe_database.items():
            # Skip CWEs that have no relevant sinks in the generated code
            if not self._contains_relevant_sink(cwe_id, generated_code):
                continue
            for sample in samples:
                similarity = self._calculate_similarity(generated_code, sample['code'])
                
                if similarity > 0.6:  # Threshold for considering code similar
                    # Find the most similar code section
                    vuln_snippet = self._find_vulnerable_section(generated_code, sample['code'])
                    # Validate the hit with sink presence and AST confirmation
                    if not self._validate_similarity_hit(cwe_id, vuln_snippet['snippet']):
                        continue

                    # Slightly adjust confidence based on similarity (bounded 0..1)
                    adjusted_confidence = max(0.0, min(1.0, similarity * 0.95 + 0.05))

                    vulns.append({
                        'cwe_id': cwe_id,
                        'cwe_name': sample['cwe_name'],
                        'line_number': vuln_snippet['line_number'],
                        'description': f'Code similar to known {sample["cwe_name"]} vulnerability',
                        'code_snippet': vuln_snippet['snippet'],
                        'severity': self._get_severity(cwe_id),
                        'detection_method': 'similarity+AST',
                        'confidence': adjusted_confidence,
                        'similar_to': sample['filename']
                    })
        
        return vulns
    
    def _calculate_similarity(self, code1: str, code2: str) -> float:
        """Calculate similarity ratio between two code snippets."""
        # Strip comments and docstrings first to avoid false similarity from comments
        try:
            code1 = self._strip_comments_and_docstrings(code1)
            code2 = self._strip_comments_and_docstrings(code2)
        except Exception:
            pass  # If stripping fails, continue with original code
        
        # Normalize both codes using AST-based identifier normalization
        norm1 = self._normalize_for_similarity(code1)
        norm2 = self._normalize_for_similarity(code2)
        
        return SequenceMatcher(None, norm1, norm2).ratio()
    
    def _normalize_code(self, code: str) -> str:
        """Normalize code for comparison by removing comments and whitespace."""
        # Remove comments
        code = re.sub(r'#.*', '', code)
        # Remove docstrings
        code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
        code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
        # Normalize whitespace
        code = ' '.join(code.split())
        return code.lower()
    
    def _find_vulnerable_section(self, generated_code: str, sample_code: str) -> Dict:
        """Find the section in generated code most similar to vulnerable sample."""
        gen_lines = generated_code.splitlines()
        sample_lines = sample_code.splitlines()
        
        best_match = {'line_number': 1, 'snippet': gen_lines[0] if gen_lines else '', 'similarity': 0}
        
        # Sliding window comparison
        window_size = min(5, len(sample_lines))
        
        for i in range(len(gen_lines) - window_size + 1):
            window = '\n'.join(gen_lines[i:i+window_size])
            similarity = SequenceMatcher(None, window, '\n'.join(sample_lines[:window_size])).ratio()
            
            if similarity > best_match['similarity']:
                best_match = {
                    'line_number': i + 1,
                    'snippet': window,
                    'similarity': similarity
                }
        
        return best_match
    
    def _get_code_snippet(self, code: str, line_num: int, context_lines: int = 2) -> str:
        """Extract code snippet around the given line number."""
        lines = code.splitlines()
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = '→ ' if i == line_num - 1 else '  '
            snippet_lines.append(f"{prefix}{i+1}: {lines[i]}")
        
        return '\n'.join(snippet_lines)

    def _normalize_for_similarity(self, code: str) -> str:
        """AST-based identifier normalization for more robust similarity.

        Parses code, renames all identifiers (variables, function names, class names)
        to var1, var2, ... in a stable order using an AST NodeTransformer, then
        unparses back to source and applies _normalize_code for final cleanup.
        """
        try:
            tree = ast.parse(code)

            class IdentifierNormalizer(ast.NodeTransformer):
                def __init__(self):
                    super().__init__()
                    self.mapping: Dict[str, str] = {}
                    self.counter = 0

                def _rename(self, name: str) -> str:
                    if name not in self.mapping:
                        self.counter += 1
                        self.mapping[name] = f"var{self.counter}"
                    return self.mapping[name]

                def visit_Name(self, node: ast.Name) -> ast.AST:
                    node.id = self._rename(node.id)
                    return node

                def visit_arg(self, node: ast.arg) -> ast.AST:
                    node.arg = self._rename(node.arg)
                    return node

                def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
                    node.name = self._rename(node.name)
                    self.generic_visit(node)
                    return node

                def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
                    node.name = self._rename(node.name)
                    self.generic_visit(node)
                    return node

                def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
                    node.name = self._rename(node.name)
                    self.generic_visit(node)
                    return node

                # Do not rename attribute names (node.attr) to avoid over-normalizing library APIs

            normalizer = IdentifierNormalizer()
            normalized_tree = normalizer.visit(tree)
            ast.fix_missing_locations(normalized_tree)
            normalized_source = ast.unparse(normalized_tree)
            return self._normalize_code(normalized_source)
        except Exception:
            # Fallback to existing normalization if AST parsing or unparse fails
            return self._normalize_code(code)
    
    def _get_severity(self, cwe_id: str) -> str:
        """Map CWE ID to severity level."""
        high_severity = ['089', '078', '094', '095', '502', '798', '022', '611']
        medium_severity = ['259', '319', '321', '326', '330', '295']
        
        if cwe_id in high_severity:
            return 'HIGH'
        elif cwe_id in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _deduplicate_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """Remove duplicate vulnerabilities based on CWE ID and approximate location."""
        seen = set()
        unique = []
        
        for vuln in vulns:
            # Create a key based on CWE ID and line number (with some tolerance)
            key = (vuln['cwe_id'], vuln['line_number'] // 3)  # Group by line ranges
            
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
            else:
                # Keep the one with higher confidence
                existing_idx = next(i for i, v in enumerate(unique) 
                                   if v['cwe_id'] == vuln['cwe_id'] 
                                   and abs(v['line_number'] - vuln['line_number']) < 5)
                if vuln.get('confidence', 0) > unique[existing_idx].get('confidence', 0):
                    unique[existing_idx] = vuln
        
        return unique
    
    def get_cwe_info(self, cwe_id: str) -> Dict:
        """Get detailed information about a specific CWE."""
        return {
            'cwe_id': cwe_id,
            'cwe_name': self._get_cwe_name(cwe_id),
            'severity': self._get_severity(cwe_id),
            'sample_count': len(self.cwe_database.get(cwe_id, []))
        }


# Backwards compatibility functions
def detect_vulnerabilities(generated_code: str, vulnerable_samples_dir: str) -> List[Dict]:
    """
    Convenience function for detecting vulnerabilities.
    """
    detector = VulnerabilityDetector(vulnerable_samples_dir)
    return detector.detect_vulnerabilities(generated_code)
