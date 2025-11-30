"""
Vulnerability Detection module: Dynamically detects vulnerabilities across all CWE categories.
"""

import os
import re
import ast
from typing import List, Dict, Tuple
from difflib import SequenceMatcher
from collections import defaultdict


class VulnerabilityDetector:
    """
    Dynamically loads vulnerable code samples from CWE database and detects
    vulnerabilities in generated code using multiple detection strategies.
    """
    
    def __init__(self, vulnerable_samples_dir: str, openai_client=None):
        self.vulnerable_samples_dir = vulnerable_samples_dir
        self.cwe_database = self._load_cwe_database()
        self.vulnerability_patterns = self._initialize_patterns()
        # Optional LLM client for expansion of vulnerability findings
        self.openai_client = openai_client
    
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
            '080': 'XSS (Basic)',
            '089': 'SQL Injection',
            '094': 'Code Injection',
            '095': 'Eval Injection',
            '116': 'Improper Encoding',
            '117': 'Log Injection',
            '193': 'Off-by-one Error',
            '200': 'Information Exposure',
            '252': 'Unchecked Return Value',
            '259': 'Hard-coded Password',
            '295': 'Certificate Validation',
            '319': 'Cleartext Transmission',
            '321': 'Hard-coded Cryptographic Key',
            '326': 'Weak Encryption',
            '330': 'Weak Random',
            '331': 'Insufficient Entropy',
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
            '703': 'Improper Check',
            '730': 'Regex DoS',
            '732': 'Incorrect Permission',
            '798': 'Hard-coded Credentials',
            '835': 'Infinite Loop',
            '937': 'Using Components with Known Vulnerabilities'
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

        # Optional: LLM-based expansion to catch additional heuristic CWEs not covered by static rules.
        if self.openai_client:
            try:
                llm_extra = self._llm_expand_vulnerabilities(generated_code, unique_vulns)
                if llm_extra:
                    unique_vulns.extend(llm_extra)
                    unique_vulns = self._deduplicate_vulnerabilities(unique_vulns)
            except Exception:
                pass  # Fail silently; expansion is best-effort

        return unique_vulns

    def _llm_expand_vulnerabilities(self, code: str, existing: List[Dict]) -> List[Dict]:
        """Use LLM to suggest additional potential CWE findings.

        The OpenAI wrapper enforces code-only output; we attempt to coerce a
        structured Python list of dicts describing potential vulnerabilities.
        Expected output format (Python literal):
            [
              {"cwe_id": "022", "line_number": 5, "description": "Unvalidated file path."},
              {"cwe_id": "703", "line_number": 6, "description": "Missing exception handling."}
            ]
        """
        if not self.openai_client:
            return []

        # Build summary of existing findings to avoid duplicates
        existing_summary = []
        for v in existing:
            existing_summary.append(f"- CWE-{v['cwe_id']} line {v['line_number']}: {v['description']}")
        existing_text = "\n".join(existing_summary) or "(none)"

        prompt = (
            "Return ONLY a valid Python list literal of dictionaries describing additional CWE vulnerabilities not already listed.\n"
            "Each dict MUST have keys: cwe_id (string), line_number (int best guess), description (string).\n"
            "Do NOT repeat existing findings.\n"
            "Code under analysis:\n" + code + "\n\nExisting findings:\n" + existing_text + "\n\n" +
            "If there are no additional meaningful findings, return an empty list: []"
        )

        raw = self.openai_client.generate_code_only_response(
            prompt,
            max_tokens=800,
            allow_non_code_prompt=True,
            enforce_input_limit=False,
        )

        # Safely eval only a list structure
        llm_vulns: List[Dict] = []
        try:
            parsed = ast.literal_eval(raw.strip())
            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    cwe_id = str(item.get('cwe_id', '')).strip()
                    # Normalize CWE ID - remove 'CWE-' prefix if present
                    if cwe_id.upper().startswith('CWE-'):
                        cwe_id = cwe_id[4:]
                    line_number = int(item.get('line_number', 1)) if str(item.get('line_number', '')).isdigit() else 1
                    description = str(item.get('description', '')).strip()
                    if not cwe_id or not description:
                        continue
                    # Skip if duplicate CWE + approximate line range
                    duplicate = any(
                        v['cwe_id'] == cwe_id and abs(v['line_number'] - line_number) < 5
                        for v in existing
                    )
                    if duplicate:
                        continue
                    llm_vulns.append({
                        'cwe_id': cwe_id,
                        'cwe_name': self._get_cwe_name(cwe_id),
                        'line_number': line_number,
                        'description': description,
                        'code_snippet': self._get_code_snippet(code, line_number),
                        'severity': self._get_severity(cwe_id),
                        'detection_method': 'llm',
                        'confidence': 0.4
                    })
        except Exception:
            return []

        return llm_vulns
    
    def _pattern_based_detection(self, code: str) -> List[Dict]:
        """Detect vulnerabilities using regex patterns."""
        vulns = []
        
        for cwe_id, patterns in self.vulnerability_patterns.items():
            for pattern_dict in patterns:
                pattern = pattern_dict['pattern']
                matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_num = code[:match.start()].count('\n') + 1
                    vulns.append({
                        'cwe_id': cwe_id,
                        'cwe_name': self._get_cwe_name(cwe_id),
                        'line_number': line_num,
                        'description': pattern_dict['description'],
                        'code_snippet': self._get_code_snippet(code, line_num),
                        'severity': self._get_severity(cwe_id),
                        'detection_method': 'pattern',
                        'confidence': 0.7
                    })
        
        return vulns
    
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
                    if (isinstance(node.func, ast.Name) and node.func.id == 'open') or \
                       (isinstance(node.func, ast.Attribute) and node.func.attr == 'safe_load'):
                        if not is_in_try(node):
                            line_num = node.lineno
                            vulns.append({
                                'cwe_id': '703',
                                'cwe_name': self._get_cwe_name('703'),
                                'line_number': line_num,
                                'description': f'No exception handling for {ast.unparse(node.func)}() call (CWE-703)',
                                'code_snippet': self._get_code_snippet(code, line_num),
                                'severity': 'LOW',
                                'detection_method': 'ast-except',
                                'confidence': 0.5
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
        def is_tainted_expr(expr: ast.AST) -> bool:
            if isinstance(expr, ast.Name):
                return expr.id in tainted
            if isinstance(expr, ast.Call):
                # input(), request.args.get(...)
                if isinstance(expr.func, ast.Name) and expr.func.id == 'input':
                    return True
                if isinstance(expr.func, ast.Attribute):
                    attr = expr.func
                    if isinstance(attr.value, ast.Attribute) and getattr(attr.value, 'attr', '') in {'args', 'form'} and attr.attr == 'get':
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
                return isinstance(expr.value, ast.Name) and expr.value.id in tainted
            if isinstance(expr, ast.Subscript):
                return is_tainted_expr(expr.value) or is_tainted_expr(expr.slice)
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
                direct_taint = is_tainted_expr(value)
                inferred_taint = False
                if isinstance(value, (ast.JoinedStr, ast.BinOp)) and node_contains_sql_literals(value):
                    inferred_taint = True
                for t in node.targets:
                    if isinstance(t, ast.Name) and (direct_taint or inferred_taint):
                        tainted.add(t.id)

        # Second pass: detect sinks using tainted vars
        def get_cwe_for_sink(func_name: str) -> str:
            if func_name.endswith('.execute') or func_name == 'execute':
                return '089'
            if func_name in {'os.system', 'subprocess.run', 'subprocess.call', 'subprocess.Popen'}:
                return '078'
            if func_name in {'open'} or func_name.endswith('.open'):
                return '022'
            return ''

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                cwe_id = get_cwe_for_sink(func_name)
                if not cwe_id:
                    continue
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
                    vulns.append({
                        'cwe_id': cwe_id,
                        'cwe_name': self._get_cwe_name(cwe_id),
                        'line_number': line_num,
                        'description': f'Tainted data flows into {func_name}()',
                        'code_snippet': self._get_code_snippet(code, line_num),
                        'severity': self._get_severity(cwe_id),
                        'detection_method': 'ast-taint',
                        'confidence': 0.8
                    })

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
    
    def _similarity_based_detection(self, generated_code: str) -> List[Dict]:
        """Detect vulnerabilities by comparing with known vulnerable samples."""
        vulns = []
        
        for cwe_id, samples in self.cwe_database.items():
            for sample in samples:
                similarity = self._calculate_similarity(generated_code, sample['code'])
                
                if similarity > 0.6:  # Threshold for considering code similar
                    # Find the most similar code section
                    vuln_snippet = self._find_vulnerable_section(generated_code, sample['code'])
                    
                    vulns.append({
                        'cwe_id': cwe_id,
                        'cwe_name': sample['cwe_name'],
                        'line_number': vuln_snippet['line_number'],
                        'description': f'Code similar to known {sample["cwe_name"]} vulnerability',
                        'code_snippet': vuln_snippet['snippet'],
                        'severity': self._get_severity(cwe_id),
                        'detection_method': 'similarity',
                        'confidence': similarity,
                        'similar_to': sample['filename']
                    })
        
        return vulns
    
    def _calculate_similarity(self, code1: str, code2: str) -> float:
        """Calculate similarity ratio between two code snippets."""
        # Normalize both codes
        norm1 = self._normalize_code(code1)
        norm2 = self._normalize_code(code2)
        
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
