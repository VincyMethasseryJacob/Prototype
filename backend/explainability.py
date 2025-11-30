"""
Explainability module: Generates explanations for detected vulnerabilities and patches.
"""

from typing import List, Dict


class VulnerabilityExplainer:
    """
    Provides detailed explanations for vulnerabilities and their patches
    across all CWE categories.
    """
    
    def __init__(self):
        self.explanations = self._initialize_explanations()
        self.patch_notes = self._initialize_patch_notes()
    
    def _initialize_explanations(self) -> Dict[str, str]:
        """
        Initialize detailed explanations for each CWE.
        """
        return {
            '020': 'Improper Input Validation: The code does not properly validate input data, '
                   'allowing attackers to inject malicious input that bypasses security checks.',
            
            '022': 'Path Traversal: The code allows user-controlled file paths without proper validation, '
                   'enabling attackers to access files outside the intended directory using sequences like "../".',
            
            '078': 'OS Command Injection: The code constructs OS commands using unsanitized user input, '
                   'allowing attackers to execute arbitrary system commands.',
            
            '080': 'Cross-Site Scripting (XSS): The code includes user input in web output without proper encoding, '
                   'allowing attackers to inject malicious scripts that execute in victims\' browsers.',
            
            '089': 'SQL Injection: The code builds SQL queries using string concatenation or formatting with '
                   'unsanitized user input, allowing attackers to manipulate database queries.',
            
            '094': 'Code Injection: The code dynamically executes user-controlled data as code, '
                   'allowing attackers to run arbitrary code in the application context.',
            
            '095': 'Eval Injection: The code uses eval() or exec() with user input, '
                   'allowing attackers to execute arbitrary Python code.',
            
            '116': 'Improper Output Encoding: The code fails to properly encode output for the target context, '
                   'which can lead to injection attacks.',
            
            '117': 'Log Injection: The code writes user-controlled data to logs without sanitization, '
                   'allowing attackers to forge log entries or inject malicious content.',
            
            '193': 'Off-by-one Error: The code contains a boundary condition error in array/string indexing, '
                   'potentially causing buffer overflows or unexpected behavior.',
            
            '200': 'Information Exposure: The code inadvertently exposes sensitive information through '
                   'error messages, logs, or responses.',
            
            '252': 'Unchecked Return Value: The code fails to check return values from critical operations, '
                   'potentially missing errors or security-relevant conditions.',
            
            '259': 'Hard-coded Password: The code contains passwords directly in the source code, '
                   'making them easily discoverable by anyone with code access.',
            
            '295': 'Improper Certificate Validation: The code disables or improperly implements SSL/TLS '
                   'certificate validation, enabling man-in-the-middle attacks.',
            
            '319': 'Cleartext Transmission: The code transmits sensitive data over unencrypted channels, '
                   'allowing attackers to intercept confidential information.',
            
            '321': 'Hard-coded Cryptographic Key: The code contains cryptographic keys directly in source code, '
                   'compromising the security of encrypted data.',
            
            '326': 'Weak Encryption: The code uses outdated or weak cryptographic algorithms (e.g., DES, MD5) '
                   'that can be easily broken by attackers.',
            
            '330': 'Use of Insufficiently Random Values: The code uses weak random number generation for '
                   'security-sensitive operations, making outputs predictable.',
            
            '331': 'Insufficient Entropy: The code uses insufficient randomness in cryptographic operations, '
                   'weakening security mechanisms.',
            
            '367': 'Time-of-check Time-of-use (TOCTOU) Race Condition: The code checks a condition and then '
                   'uses the resource, but the resource state can change between check and use.',
            
            '414': 'Missing Lock Check: The code accesses shared resources without proper synchronization, '
                   'leading to race conditions.',
            
            '425': 'Direct Request: The code allows direct access to restricted resources without proper '
                   'authorization checks.',
            
            '454': 'External Initialization of Trusted Variables: The code initializes security-critical '
                   'variables from untrusted external sources.',
            
            '477': 'Use of Obsolete Function: The code uses deprecated or obsolete functions with known '
                   'security vulnerabilities.',
            
            '502': 'Deserialization of Untrusted Data: The code deserializes data from untrusted sources '
                   'without validation, allowing arbitrary code execution.',
            
            '522': 'Insufficiently Protected Credentials: The code stores or transmits credentials using '
                   'inadequate protection mechanisms.',
            
            '595': 'Comparison of Object References Instead of Contents: The code compares object references '
                   'when it should compare contents, leading to logic errors.',
            
            '605': 'Multiple Binds to Same Port: The code attempts to bind multiple sockets to the same port, '
                   'causing conflicts.',
            
            '611': 'XML External Entity (XXE) Injection: The code processes XML with external entity resolution '
                   'enabled, allowing attackers to access local files or launch DoS attacks.',
            
            '703': 'Improper Check or Handling of Exceptional Conditions: The code fails to properly handle '
                   'errors and exceptions, potentially exposing sensitive information.',
            
            '730': 'Regular Expression Denial of Service (ReDoS): The code uses complex regex patterns on '
                   'user input, enabling attackers to cause excessive CPU consumption.',
            
            '732': 'Incorrect Permission Assignment: The code creates files or resources with overly permissive '
                   'access controls.',
            
            '798': 'Hard-coded Credentials: The code contains usernames, passwords, API keys, or other '
                   'credentials directly in source code.',
            
            '835': 'Infinite Loop: The code contains a loop without proper exit conditions, '
                   'potentially causing denial of service.',
        }
    
    def _initialize_patch_notes(self) -> Dict[str, str]:
        """
        Initialize patch recommendations for each CWE.
        """
        return {
            '020': 'Implement comprehensive input validation using allowlists, type checking, and sanitization. '
                   'Validate length, format, and content against expected patterns.',
            
            '022': 'Use secure path handling: validate and sanitize file paths, restrict access to allowed directories, '
                   'resolve canonical paths, and check for directory traversal sequences.',
            
            '078': 'Avoid constructing OS commands from user input. Use safe APIs with parameterized arguments. '
                   'If unavoidable, use strict allowlists and proper escaping.',
            
            '080': 'Apply context-appropriate output encoding (HTML entity encoding, JavaScript escaping). '
                   'Use security libraries and frameworks that auto-escape output.',
            
            '089': 'Use parameterized queries (prepared statements) instead of string concatenation. '
                   'This separates SQL code from data, preventing injection attacks.',
            
            '094': 'Avoid dynamic code execution. Use safe alternatives like configuration files or '
                   'predefined function mappings instead of eval/exec.',
            
            '095': 'Never use eval() or exec() with user input. Use ast.literal_eval() for safe evaluation '
                   'of literals, or implement a safe expression parser.',
            
            '116': 'Apply proper encoding for the output context (HTML, URL, JSON, etc.). '
                   'Use framework-provided encoding functions.',
            
            '117': 'Sanitize log input by removing/encoding special characters. Use structured logging '
                   'with separate fields for user data.',
            
            '193': 'Carefully review array/string bounds. Use length checks and consider using safer '
                   'slice operations instead of direct indexing.',
            
            '200': 'Implement generic error messages for users. Log detailed errors securely without '
                   'exposing sensitive information in responses.',
            
            '252': 'Always check return values from security-critical operations. Implement proper error '
                   'handling and fail securely.',
            
            '259': 'Remove hard-coded passwords. Use environment variables, secure configuration files, '
                   'or credential management systems (e.g., AWS Secrets Manager, HashiCorp Vault).',
            
            '295': 'Enable proper certificate validation. Never disable SSL verification in production. '
                   'Use system certificate stores and implement certificate pinning if needed.',
            
            '319': 'Use encrypted protocols (HTTPS, TLS) for all sensitive data transmission. '
                   'Enforce secure connections and reject cleartext fallback.',
            
            '321': 'Remove hard-coded keys. Generate keys dynamically, store them securely (e.g., key vaults), '
                   'and use environment-specific keys.',
            
            '326': 'Use strong, modern cryptographic algorithms: AES-256 for encryption, SHA-256+ for hashing, '
                   'RSA-2048+ or ECC for asymmetric crypto.',
            
            '330': 'Use cryptographically secure random number generators (secrets module in Python) '
                   'for security-sensitive operations.',
            
            '331': 'Ensure sufficient entropy for cryptographic operations. Use os.urandom() or secrets module, '
                   'never standard random() for security.',
            
            '367': 'Implement atomic operations or use proper locking mechanisms. Minimize time between '
                   'check and use, or redesign to avoid TOCTOU conditions.',
            
            '414': 'Use proper synchronization mechanisms (locks, semaphores) when accessing shared resources. '
                   'Follow thread-safe programming practices.',
            
            '425': 'Implement proper access control checks before allowing access to resources. '
                   'Verify user authorization for each request.',
            
            '454': 'Initialize security-critical variables from trusted sources only. Validate external '
                   'configuration and use secure defaults.',
            
            '477': 'Update to modern, supported APIs. Replace obsolete functions with current secure alternatives '
                   'and keep dependencies updated.',
            
            '502': 'Avoid deserializing untrusted data. If necessary, use safe formats (JSON), implement '
                   'integrity checks, and restrict deserialization to safe classes.',
            
            '522': 'Encrypt credentials at rest and in transit. Use secure storage mechanisms and '
                   'avoid logging or exposing credentials.',
            
            '595': 'Use proper comparison methods for object contents (== for values, is for identity). '
                   'Understand the difference and use appropriately.',
            
            '605': 'Use unique ports or implement proper port management. Set SO_REUSEADDR carefully '
                   'and validate port availability.',
            
            '611': 'Disable external entity resolution in XML parsers. Use defusedxml library or configure '
                   'parsers to reject DTDs and external entities.',
            
            '703': 'Implement comprehensive error handling with try-except blocks. Log errors securely '
                   'and provide generic messages to users.',
            
            '730': 'Limit regex complexity and input length. Use timeouts for regex operations. '
                   'Validate input before applying complex patterns.',
            
            '732': 'Set minimal required permissions (principle of least privilege). Use umask or explicit '
                   'permission settings when creating files.',
            
            '798': 'Remove all hard-coded credentials. Use environment variables, secure vaults, or '
                   'configuration management systems. Rotate credentials regularly.',
            
            '835': 'Ensure all loops have proper exit conditions. Implement timeouts and iteration limits. '
                   'Validate loop control variables.',
        }
    
    def generate_explanation(self, vuln: Dict) -> Dict:
        """
        Generate a detailed explanation for a single vulnerability.
        """
        cwe_id = vuln.get('cwe_id', 'Unknown')
        
        explanation = self.explanations.get(
            cwe_id,
            f"A vulnerability was detected related to CWE-{cwe_id}. This represents a security weakness "
            f"that could be exploited by attackers."
        )
        
        patch_note = self.patch_notes.get(
            cwe_id,
            "Apply secure coding practices and follow security guidelines for this vulnerability type."
        )
        
        vuln['explanation'] = explanation
        vuln['patch_note'] = patch_note
        vuln['remediation_priority'] = self._get_remediation_priority(vuln)
        
        return vuln
    
    def _get_remediation_priority(self, vuln: Dict) -> str:
        """
        Determine remediation priority based on severity and confidence.
        """
        severity = vuln.get('severity', 'LOW')
        confidence = vuln.get('confidence', 0.5)
        
        if severity == 'HIGH' and confidence > 0.7:
            return 'CRITICAL'
        elif severity == 'HIGH':
            return 'HIGH'
        elif severity == 'MEDIUM' and confidence > 0.7:
            return 'HIGH'
        elif severity == 'MEDIUM':
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_explanations(self, vuln_list: List[Dict]) -> List[Dict]:
        """
        Generate explanations for a list of vulnerabilities.
        """
        return [self.generate_explanation(v) for v in vuln_list]
    
    def generate_summary_report(self, vuln_list: List[Dict]) -> Dict:
        """
        Generate a summary report of all vulnerabilities.
        """
        if not vuln_list:
            return {
                'total_vulnerabilities': 0,
                'severity_breakdown': {},
                'cwe_breakdown': {},
                'message': 'No vulnerabilities detected.'
            }
        
        severity_count = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        cwe_count = {}
        
        for vuln in vuln_list:
            severity = vuln.get('severity', 'LOW')
            severity_count[severity] = severity_count.get(severity, 0) + 1
            
            cwe_id = vuln.get('cwe_id', 'Unknown')
            cwe_name = vuln.get('cwe_name', f'CWE-{cwe_id}')
            cwe_key = f"{cwe_id}: {cwe_name}"
            cwe_count[cwe_key] = cwe_count.get(cwe_key, 0) + 1
        
        return {
            'total_vulnerabilities': len(vuln_list),
            'severity_breakdown': severity_count,
            'cwe_breakdown': cwe_count,
            'high_priority_count': sum(1 for v in vuln_list if v.get('remediation_priority') in ['CRITICAL', 'HIGH']),
            'unique_cwe_count': len(cwe_count)
        }


# Backwards compatibility function
def generate_explanations(vuln_list: list) -> list:
    """
    For each vulnerability, generate a plain-language explanation and patch note.
    """
    explainer = VulnerabilityExplainer()
    return explainer.generate_explanations(vuln_list)
