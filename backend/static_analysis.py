"""
Static Analysis module: Runs Bandit and secondary tool (Semgrep) for vulnerability detection.
"""
import subprocess
import tempfile
import json
import os
import re
from typing import Dict, List


def strip_markdown_code_fences(code: str) -> str:
    """
    Remove markdown code fences from code string.
    
    Args:
        code: Code string that may contain markdown fences like ```python or ```
    
    Returns:
        Clean code without markdown fences
    """
    # Remove opening fence with optional language specifier
    code = re.sub(r'^```[\w]*\s*\n', '', code, flags=re.MULTILINE)
    # Remove closing fence
    code = re.sub(r'\n```\s*$', '', code, flags=re.MULTILINE)
    # Also handle fences in the middle
    code = re.sub(r'```[\w]*\s*\n', '', code)
    code = re.sub(r'\n```', '', code)
    
    return code.strip()


class StaticAnalyzer:
    """
    Runs static analysis tools on code to detect vulnerabilities.
    Supports Bandit (primary) and Semgrep (secondary).
    """
    
    def __init__(self):
        self.tools_available = self._check_tools()
    
    def _check_tools(self) -> Dict[str, bool]:
        """Check which static analysis tools are available."""
        tools = {}
        
        # Check Bandit
        try:
            subprocess.run(['bandit', '--version'], capture_output=True, check=True)
            tools['bandit'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            tools['bandit'] = False
        
        # Check Semgrep
        try:
            subprocess.run(['semgrep', '--version'], capture_output=True, check=True)
            tools['semgrep'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            tools['semgrep'] = False
        
        return tools
    
    def run_bandit(self, code: str, code_path: str = None) -> Dict:
        """
        Run Bandit on the given code and return results.
        
        Args:
            code: Python code string to analyze
            code_path: Optional path to existing file (if None, creates temp file)
        
        Returns:
            Dict with 'issues', 'summary', 'raw_output', and 'success'
        """
        if not self.tools_available.get('bandit', False):
            return {
                'success': False,
                'error': 'Bandit is not installed. Install with: pip install bandit',
                'issues': [],
                'summary': {}
            }
        
        # Strip markdown code fences if present
        code = strip_markdown_code_fences(code)
        
        # Create temporary file if no path provided
        temp_file = None
        if code_path is None:
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8')
            temp_file.write(code)
            temp_file.flush()
            code_path = temp_file.name
        
        try:
            # Run Bandit with JSON output
            result = subprocess.run(
                ['bandit', '-r', code_path, '-f', 'json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Bandit returns non-zero if issues found, which is expected
            output = result.stdout
            
            try:
                bandit_data = json.loads(output)
            except json.JSONDecodeError:
                return {
                    'success': False,
                    'error': 'Failed to parse Bandit output',
                    'raw_output': output,
                    'issues': [],
                    'summary': {}
                }
            
            # Extract issues
            issues = []
            for result_item in bandit_data.get('results', []):
                issues.append({
                    'test_id': result_item.get('test_id'),
                    'test_name': result_item.get('test_name'),
                    'severity': result_item.get('issue_severity'),
                    'confidence': result_item.get('issue_confidence'),
                    'cwe_id': result_item.get('issue_cwe', {}).get('id') if result_item.get('issue_cwe') else None,
                    'line_number': result_item.get('line_number'),
                    'code': result_item.get('code'),
                    'description': result_item.get('issue_text'),
                    'more_info': result_item.get('more_info')
                })
            
            # Extract summary
            metrics = bandit_data.get('metrics', {})
            total_issues = sum(
                sum(sev_dict.values())
                for file_metrics in metrics.values()
                for sev_dict in [file_metrics.get('SEVERITY', {})]
            )
            
            summary = {
                'total_issues': total_issues,
                'severity_breakdown': self._aggregate_severity(bandit_data),
                'confidence_breakdown': self._aggregate_confidence(bandit_data),
                'files_analyzed': len(metrics)
            }
            
            return {
                'success': True,
                'issues': issues,
                'summary': summary,
                'raw_output': output
            }
        
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Bandit analysis timed out',
                'issues': [],
                'summary': {}
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Error running Bandit: {str(e)}',
                'issues': [],
                'summary': {}
            }
        finally:
            # Clean up temporary file
            if temp_file:
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
    
    def _aggregate_severity(self, bandit_data: Dict) -> Dict[str, int]:
        """Aggregate severity counts from Bandit data."""
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNDEFINED': 0}
        
        for result in bandit_data.get('results', []):
            severity = result.get('issue_severity', 'UNDEFINED')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return severity_counts
    
    def _aggregate_confidence(self, bandit_data: Dict) -> Dict[str, int]:
        """Aggregate confidence counts from Bandit data."""
        confidence_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNDEFINED': 0}
        
        for result in bandit_data.get('results', []):
            confidence = result.get('issue_confidence', 'UNDEFINED')
            confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
        
        return confidence_counts
    
    def run_semgrep(self, code: str, code_path: str = None, config: str = "auto") -> Dict:
        """
        Run Semgrep on the given code and return results.
        
        Args:
            code: Python code string to analyze
            code_path: Optional path to existing file
            config: Semgrep config (default "auto" uses built-in rules). You can pass a ruleset or path.
        
        Returns:
            Dict with 'issues', 'summary', 'raw_output', and 'success'
        """
        if not self.tools_available.get('semgrep', False):
            return {
                'success': False,
                'error': 'Semgrep is not installed. Install from https://semgrep.dev/docs/ or via pip/installer',
                'issues': [],
                'summary': {}
            }

        code = strip_markdown_code_fences(code)

        temp_file = None
        if code_path is None:
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8')
            temp_file.write(code)
            temp_file.flush()
            code_path = temp_file.name

        try:
            # Semgrep JSON output
            env = os.environ.copy()
            env.setdefault('PYTHONIOENCODING', 'utf-8')
            env.setdefault('PYTHONUTF8', '1')
            result = subprocess.run(
                ['semgrep', '--json', '--config', config, code_path],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=60,
                env=env
            )
            output = result.stdout

            try:
                data = json.loads(output) if output.strip() else {}
            except json.JSONDecodeError:
                return {
                    'success': False,
                    'error': 'Failed to parse Semgrep output',
                    'raw_output': output,
                    'issues': [],
                    'summary': {}
                }

            findings = []
            # Map Semgrep severity to Bandit-style
            semgrep_severity_map = {
                'ERROR': 'HIGH',
                'WARNING': 'MEDIUM',
                'INFO': 'LOW',
                'MEDIUM': 'MEDIUM',
                'HIGH': 'HIGH',
                'LOW': 'LOW'
            }
            for r in data.get('results', []):
                extra = r.get('extra', {})
                raw_severity = (extra.get('severity') or 'MEDIUM').upper()
                severity = semgrep_severity_map.get(raw_severity, 'MEDIUM')
                # semgrep often includes metadata.cwe: ["CWE-089"]
                meta = extra.get('metadata', {})
                cwes = meta.get('cwe') or []
                cwe_id = None
                if isinstance(cwes, list) and cwes:
                    first = str(cwes[0])
                    if first.upper().startswith('CWE-'):
                        cwe_val = first[4:]
                    else:
                        cwe_val = first
                    # If the value contains a colon, split and take only the number part
                    if ':' in cwe_val:
                        cwe_id = cwe_val.split(':')[0].strip()
                    else:
                        cwe_id = cwe_val.strip()

                findings.append({
                    'check_id': r.get('check_id'),
                    'path': r.get('path'),
                    'start': r.get('start', {}),
                    'end': r.get('end', {}),
                    'severity': severity,
                    'message': extra.get('message') or '',
                    'cwe_id': cwe_id,
                })

            summary = {
                'total_issues': len(findings),
                'severity_breakdown': {
                    'HIGH': sum(1 for f in findings if f['severity'] == 'HIGH'),
                    'MEDIUM': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
                    'LOW': sum(1 for f in findings if f['severity'] == 'LOW')
                }
            }

            return {
                'success': True,
                'issues': findings,
                'summary': summary,
                'raw_output': output
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Semgrep analysis timed out',
                'issues': [],
                'summary': {}
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Error running Semgrep: {str(e)}',
                'issues': [],
                'summary': {}
            }
        finally:
            if temp_file:
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
    
    def run_secondary_tool(self, code: str, tool: str = 'semgrep') -> Dict:
        """
        Run a secondary static analyzer.
        
        Args:
            code: Python code to analyze
            tool: Tool name ('semgrep' is currently supported)
        
        Returns:
            Analysis results dictionary
        """
        if tool.lower() == 'semgrep':
            return self.run_semgrep(code)
        else:
            return {
                'success': False,
                'error': f'Tool {tool} not supported',
                'issues': [],
                'summary': {}
            }
    
    def compare_results(self, bandit_results: Dict, secondary_results: Dict) -> Dict:
        """
        Compare results from Bandit and secondary tool to identify overlaps and differences.
        
        Returns:
            Dict with comparison statistics
        """
        bandit_issues = bandit_results.get('issues', [])
        secondary_issues = secondary_results.get('issues', [])
        
        # Extract CWE IDs from both
        bandit_cwes = set(issue.get('cwe_id') for issue in bandit_issues if issue.get('cwe_id'))
        secondary_cwes = set(issue.get('cwe_id') for issue in secondary_issues if issue.get('cwe_id'))
        
        # Extract line numbers - handle different formats
        # Bandit uses 'line_number' directly
        bandit_lines = set(issue.get('line_number') for issue in bandit_issues if issue.get('line_number'))
        
        # Semgrep uses 'start'/'end' dictionaries - extract 'line' from 'start'
        secondary_lines = set()
        for issue in secondary_issues:
            line = None
            if 'start' in issue and isinstance(issue['start'], dict):
                line = issue['start'].get('line')
            elif 'line_number' in issue:
                line = issue['line_number']
            if line:
                secondary_lines.add(line)
        
        # Calculate overlaps by line and by CWE
        overlapping_lines = bandit_lines.intersection(secondary_lines)
        overlapping_cwes = bandit_cwes.intersection(secondary_cwes)
        
        return {
            'bandit_total': len(bandit_issues),
            'secondary_total': len(secondary_issues),
            'bandit_unique_cwes': len(bandit_cwes),
            'secondary_unique_cwes': len(secondary_cwes),
            'overlapping_lines': len(overlapping_lines),
            'overlapping_cwes': len(overlapping_cwes),
            'bandit_only_lines': len(bandit_lines - secondary_lines),
            'secondary_only_lines': len(secondary_lines - bandit_lines),
            'bandit_only_cwes': len(bandit_cwes - secondary_cwes),
            'secondary_only_cwes': len(secondary_cwes - bandit_cwes),
            'bandit_severity': bandit_results.get('summary', {}).get('severity_breakdown', {}),
            'secondary_types': secondary_results.get('summary', {}).get('type_breakdown', {})
        }
    
    def compare_three_tools(self, custom_vulns: List[Dict], bandit_results: Dict, secondary_results: Dict) -> Dict:
        """
        Compare results from all three tools: Custom Detector, Bandit, and Semgrep.
        
        Args:
            custom_vulns: List of vulnerabilities from custom detector
            bandit_results: Results from Bandit analysis
            secondary_results: Results from Semgrep analysis
        
        Returns:
            Dict with 3-way comparison statistics including overlaps between all tools
        """
        bandit_issues = bandit_results.get('issues', [])
        secondary_issues = secondary_results.get('issues', [])
        
        # Extract CWE IDs from all three tools
        # IMPORTANT: Normalize all CWE IDs to just the number (e.g., "089") for comparison
        def normalize_cwe(cwe_val):
            """Normalize CWE value to 3-digit number format (e.g., '089' from 'CWE-089: SQL')"""
            if not cwe_val:
                return None
            cwe_str = str(cwe_val).strip().upper()
            # Remove 'CWE-' prefix if present
            if cwe_str.startswith('CWE-'):
                cwe_str = cwe_str[4:]
            # Split on ':' or ' ' to remove descriptions
            cwe_str = cwe_str.split(':')[0].split()[0].strip()
            # Ensure it's numeric and pad to 3 digits
            if cwe_str.isdigit():
                return cwe_str.zfill(3)  # Pad to 3 digits: '78' -> '078'
            return None
        
        custom_cwes = set(normalize_cwe(v.get('cwe_id')) for v in custom_vulns if v.get('cwe_id'))
        
        # Bandit returns issue_cwe as a dict: {"id": 502, "link": "..."}
        bandit_cwes = set()
        for issue in bandit_issues:
            cwe_val = None
            if 'issue_cwe' in issue and isinstance(issue['issue_cwe'], dict):
                cwe_val = issue['issue_cwe'].get('id')
            elif 'cwe_id' in issue:
                cwe_val = issue.get('cwe_id')
            normalized = normalize_cwe(cwe_val)
            if normalized:
                bandit_cwes.add(normalized)
        
        secondary_cwes = set(normalize_cwe(issue.get('cwe_id')) for issue in secondary_issues if issue.get('cwe_id'))
        
        # Remove None values
        custom_cwes.discard(None)
        bandit_cwes.discard(None)
        secondary_cwes.discard(None)
        
        # Debug: Show what CWE IDs we extracted
        print(f"\n[DEBUG] compare_three_tools CWE extraction:")
        print(f"   Custom CWEs: {custom_cwes}")
        print(f"   Bandit CWEs: {bandit_cwes}")
        print(f"   Semgrep CWEs: {secondary_cwes}")
        
        # Extract line numbers from all three tools
        # Custom detector uses 'line_number' or 'line'
        custom_lines = set()
        for v in custom_vulns:
            line = v.get('line_number') or v.get('line')
            if line:
                custom_lines.add(line)
        
        # Bandit uses 'line_number'
        bandit_lines = set(issue.get('line_number') for issue in bandit_issues if issue.get('line_number'))
        
        # Semgrep uses 'start'/'end' dictionaries
        secondary_lines = set()
        for issue in secondary_issues:
            line = None
            if 'start' in issue and isinstance(issue['start'], dict):
                line = issue['start'].get('line')
            elif 'line_number' in issue:
                line = issue['line_number']
            if line:
                secondary_lines.add(line)
        
        # Helper function to build detailed overlap info (CWE-line pairs)
        def get_cwe_line_pairs(vulns, tool_name='custom'):
            """Extract (CWE ID, line number) pairs from vulnerabilities."""
            pairs = {}
            for v in vulns:
                cwe = v.get('cwe_id')
                line = v.get('line_number') or v.get('line')
                if cwe and line:
                    key = (cwe, line)
                    if key not in pairs:
                        pairs[key] = {'cwe': cwe, 'line': line, 'tool': tool_name}
            return pairs
        
        def get_bandit_cwe_line_pairs(issues):
            """Extract (CWE ID, line number) pairs from Bandit issues."""
            pairs = {}
            for issue in issues:
                cwe = issue.get('cwe_id')
                line = issue.get('line_number')
                if cwe and line:
                    key = (cwe, line)
                    if key not in pairs:
                        pairs[key] = {'cwe': cwe, 'line': line, 'tool': 'bandit'}
            return pairs
        
        def get_semgrep_cwe_line_pairs(issues):
            """Extract (CWE ID, line number) pairs from Semgrep issues."""
            pairs = {}
            for issue in issues:
                cwe = issue.get('cwe_id')
                line = None
                if 'start' in issue and isinstance(issue['start'], dict):
                    line = issue['start'].get('line')
                elif 'line_number' in issue:
                    line = issue['line_number']
                if cwe and line:
                    key = (cwe, line)
                    if key not in pairs:
                        pairs[key] = {'cwe': cwe, 'line': line, 'tool': 'semgrep'}
            return pairs
        
        # Get detailed pairs for each tool
        custom_pairs = get_cwe_line_pairs(custom_vulns, 'custom')
        bandit_pairs = get_bandit_cwe_line_pairs(bandit_issues)
        semgrep_pairs = get_semgrep_cwe_line_pairs(secondary_issues)
        
        # Calculate 2-way overlaps (by line)
        custom_bandit_lines = custom_lines.intersection(bandit_lines)
        custom_secondary_lines = custom_lines.intersection(secondary_lines)
        bandit_secondary_lines = bandit_lines.intersection(secondary_lines)
        
        # Calculate 3-way overlap (by line) - found by all three tools
        three_way_lines = custom_lines.intersection(bandit_lines).intersection(secondary_lines)
        
        # Calculate 2-way overlaps (by CWE)
        custom_bandit_cwes = custom_cwes.intersection(bandit_cwes)
        custom_secondary_cwes = custom_cwes.intersection(secondary_cwes)
        bandit_secondary_cwes = bandit_cwes.intersection(secondary_cwes)
        
        # Calculate 3-way overlap (by CWE) - found by all three tools
        three_way_cwes = custom_cwes.intersection(bandit_cwes).intersection(secondary_cwes)
        
        # Debug: Show overlaps
        print(f"   Custom-Bandit CWE overlap: {custom_bandit_cwes}")
        print(f"   Custom-Semgrep CWE overlap: {custom_secondary_cwes}")
        print(f"   Bandit-Semgrep CWE overlap: {bandit_secondary_cwes}")
        print(f"   3-Way CWE overlap: {three_way_cwes}")
        
        # Build detailed overlap lists (CWE + line pairs that overlap)
        custom_bandit_overlap_details = []
        for pair in custom_pairs:
            if pair in bandit_pairs:
                custom_bandit_overlap_details.append(pair)
        
        custom_semgrep_overlap_details = []
        for pair in custom_pairs:
            if pair in semgrep_pairs:
                custom_semgrep_overlap_details.append(pair)
        
        bandit_semgrep_overlap_details = []
        for pair in bandit_pairs:
            if pair in semgrep_pairs:
                bandit_semgrep_overlap_details.append(pair)
        
        three_way_overlap_details = []
        for pair in custom_pairs:
            if pair in bandit_pairs and pair in semgrep_pairs:
                three_way_overlap_details.append(pair)
        
        # IMPORTANT: The counts should match the CWE overlaps, not just the pair overlaps
        # If custom_bandit_cwes = {078, 089}, the details should show those CWEs
        # Build CWE-only details (not requiring same line number)
        custom_bandit_cwe_details = list(custom_bandit_cwes)
        custom_semgrep_cwe_details = list(custom_secondary_cwes)
        bandit_semgrep_cwe_details = list(bandit_secondary_cwes)
        three_way_cwe_details = list(three_way_cwes)
        
        # Calculate unique detections (found by only one tool)
        all_lines = custom_lines.union(bandit_lines).union(secondary_lines)
        custom_only_lines = custom_lines - bandit_lines - secondary_lines
        bandit_only_lines = bandit_lines - custom_lines - secondary_lines
        secondary_only_lines = secondary_lines - custom_lines - bandit_lines
        
        all_cwes = custom_cwes.union(bandit_cwes).union(secondary_cwes)
        custom_only_cwes = custom_cwes - bandit_cwes - secondary_cwes
        bandit_only_cwes = bandit_cwes - custom_cwes - secondary_cwes
        secondary_only_cwes = secondary_cwes - custom_cwes - bandit_cwes
        
        # Calculate overlap rates
        total_unique_lines = len(all_lines)
        total_unique_cwes = len(all_cwes)
        
        three_way_line_rate = len(three_way_lines) / total_unique_lines if total_unique_lines > 0 else 0.0
        three_way_cwe_rate = len(three_way_cwes) / total_unique_cwes if total_unique_cwes > 0 else 0.0
        
        return {
            # Tool totals
            'custom_total': len(custom_vulns),
            'bandit_total': len(bandit_issues),
            'secondary_total': len(secondary_issues),
            
            # Unique CWEs per tool
            'custom_unique_cwes': len(custom_cwes),
            'bandit_unique_cwes': len(bandit_cwes),
            'secondary_unique_cwes': len(secondary_cwes),
            
            # 2-way overlaps (lines)
            'custom_bandit_overlap_lines': len(custom_bandit_lines),
            'custom_secondary_overlap_lines': len(custom_secondary_lines),
            'bandit_secondary_overlap_lines': len(bandit_secondary_lines),
            
            # 2-way overlaps (CWEs)
            'custom_bandit_overlap_cwes': len(custom_bandit_cwes),
            'custom_secondary_overlap_cwes': len(custom_secondary_cwes),
            'bandit_secondary_overlap_cwes': len(bandit_secondary_cwes),
            
            # 3-way overlap (all tools agree)
            'three_way_overlap_lines': len(three_way_lines),
            'three_way_overlap_cwes': len(three_way_cwes),
            'three_way_line_rate': round(three_way_line_rate, 3),
            'three_way_cwe_rate': round(three_way_cwe_rate, 3),
            
            # Unique to each tool (lines)
            'custom_only_lines': len(custom_only_lines),
            'bandit_only_lines': len(bandit_only_lines),
            'secondary_only_lines': len(secondary_only_lines),
            
            # Unique to each tool (CWEs)
            'custom_only_cwes': len(custom_only_cwes),
            'bandit_only_cwes': len(bandit_only_cwes),
            'secondary_only_cwes': len(secondary_only_cwes),
            
            # Totals
            'total_unique_lines': total_unique_lines,
            'total_unique_cwes': total_unique_cwes,
            
            # Detailed overlap information (CWE-line pairs)
            'custom_bandit_overlap_details': list(custom_bandit_overlap_details),
            'custom_secondary_overlap_details': list(custom_semgrep_overlap_details),
            'bandit_secondary_overlap_details': list(bandit_semgrep_overlap_details),
            'three_way_overlap_details': list(three_way_overlap_details),
            
            # CWE-only overlap details (for compatibility with counts)
            'custom_bandit_overlap_cwes_list': custom_bandit_cwe_details,
            'custom_secondary_overlap_cwes_list': custom_semgrep_cwe_details,
            'bandit_secondary_overlap_cwes_list': bandit_semgrep_cwe_details,
            'three_way_overlap_cwes_list': three_way_cwe_details,
            
            # Tool summaries
            'custom_severity': self._calculate_severity_breakdown(custom_vulns),
            'bandit_severity': bandit_results.get('summary', {}).get('severity_breakdown', {}),
            'secondary_severity': secondary_results.get('summary', {}).get('severity_breakdown', {})
        }
    
    def _calculate_severity_breakdown(self, vulns: List[Dict]) -> Dict[str, int]:
        """Calculate severity breakdown for custom detector results."""
        breakdown = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNDEFINED': 0}
        for v in vulns:
            severity = v.get('severity', 'UNDEFINED')
            if severity in breakdown:
                breakdown[severity] += 1
            else:
                breakdown['UNDEFINED'] += 1
        return breakdown


# Backwards compatibility functions
def run_bandit(code_path: str) -> dict:
    """
    Run Bandit on the given code file and return results.
    """
    analyzer = StaticAnalyzer()
    with open(code_path, 'r', encoding='utf-8') as f:
        code = f.read()
    return analyzer.run_bandit(code, code_path)


def run_secondary_tool(code_path: str) -> dict:
    """
    Run a secondary static analyzer (Semgrep) and return results.
    """
    analyzer = StaticAnalyzer()
    with open(code_path, 'r', encoding='utf-8') as f:
        code = f.read()
    return analyzer.run_semgrep(code, code_path)
